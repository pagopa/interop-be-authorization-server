package it.pagopa.interop.clientassertionvalidation

import cats.data._
import cats.syntax.all._
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.model._
import it.pagopa.interop.commons.utils.TypeConversions._
import it.pagopa.interop.commons.utils.{DIGEST_CLAIM, PURPOSE_ID_CLAIM}

import java.util.UUID
import scala.jdk.CollectionConverters._
import scala.util.{Failure, Success, Try}

trait ClientAssertionValidator {
  def validateClientAssertion(
    clientAssertionJws: String,
    clientId: Option[UUID]
  ): Either[NonEmptyList[ClientAssertionValidationError], AssertionValidationResult]

  def verifySignature(
    validationResult: AssertionValidationResult,
    publicKey: String
  ): Either[ClientAssertionValidationError, Unit]
}

final class NimbusClientAssertionValidator(expectedAudience: Set[String]) extends ClientAssertionValidator {
  private val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
    new DefaultJWTClaimsVerifier[SecurityContext](null, null, null, null)

  val SHA_256: String = "SHA256"

  override def validateClientAssertion(
    clientAssertionJws: String,
    clientId: Option[UUID]
  ): Either[NonEmptyList[ClientAssertionValidationError], AssertionValidationResult] =
    for {
      jwt             <- parseClientAssertion(clientAssertionJws)
      clientAssertion <- verifyClaims(jwt, clientId, clientAssertionJws)
    } yield AssertionValidationResult(clientAssertion, jwt)

  override def verifySignature(
    validationResult: AssertionValidationResult,
    publicKey: String
  ): Either[ClientAssertionValidationError, Unit] =
    for {
      verifier         <- rsaVerifier(publicKey)
      signatureIsValid <- Try(validationResult.jwt.verify(verifier)).toEither.leftMap(ex =>
        ClientAssertionVerificationError(ex.getMessage)
      )
      _                <- Left(InvalidClientAssertionSignature).withRight[Unit].unlessA(signatureIsValid)
    } yield ()

  private def verifyClaims(
    jwt: SignedJWT,
    clientId: Option[UUID],
    clientAssertion: String
  ): Either[NonEmptyList[ClientAssertionValidationError], ClientAssertion] =
    (
      validateStandardClaims(jwt),
      getOrFail(jwt.getHeader.getKeyID, KidNotFound),
      getOrFail(jwt.getHeader.getAlgorithm.getName, AlgorithmNotFound),
      subjectClaim(clientId, jwt.getJWTClaimsSet.getSubject),
      purposeIdClaim(jwt.getJWTClaimsSet.getStringClaim(PURPOSE_ID_CLAIM)),
      getOrFail(jwt.getJWTClaimsSet.getJWTID, JtiNotFound),
      getOrFail(jwt.getJWTClaimsSet.getIssueTime.getTime, IssuedAtNotFound),
      getOrFail(jwt.getJWTClaimsSet.getIssuer, IssuerNotFound),
      audience(jwt.getJWTClaimsSet.getAudience.asScala.toSet, expectedAudience),
      getOrFail(jwt.getJWTClaimsSet.getExpirationTime.getTime, ExpirationNotFound),
      digestClaim(jwt.getJWTClaimsSet)
    ).tupled.map { case (_, kid, algorithm, subject, purposeId, jti, issuedAt, issuer, audience, expiration, digest) =>
      ClientAssertion(
        kid = kid,
        alg = algorithm,
        sub = subject,
        purposeId = purposeId,
        jti = jti,
        iat = issuedAt,
        iss = issuer,
        aud = audience,
        exp = expiration,
        digest = digest,
        raw = clientAssertion
      )
    }.toEither

  private def parseClientAssertion(
    clientAssertion: String
  ): Either[NonEmptyList[ClientAssertionParseFailed], SignedJWT] =
    Try(SignedJWT.parse(clientAssertion)).toEither.leftMap(ex =>
      NonEmptyList.one(ClientAssertionParseFailed(ex.getMessage))
    )

  private def validateStandardClaims(jwt: SignedJWT): ValidatedNel[ClientAssertionInvalidClaims, Unit] =
    Try(claimsVerifier.verify(jwt.getJWTClaimsSet, null)).toEither
      .leftMap(ex => ClientAssertionInvalidClaims(ex.getMessage))
      .toValidatedNel

  private def getOrFail[E, T](value: => T, error: => E): ValidatedNel[E, T] =
    Try(Option(value)) match {
      case Failure(_) | Success(None) => error.invalidNel
      case Success(Some(v))           => v.validNel
    }

  private def rsaVerifier(publicKeyJwk: String): Either[PublicKeyParseFailed, RSASSAVerifier] = Try {
    val jwk: JWK  = JWK.parse(publicKeyJwk)
    val publicKey = jwk.toRSAKey
    new RSASSAVerifier(publicKey)
  }.toEither.leftMap(ex => PublicKeyParseFailed(ex.getMessage))

  private def subjectClaim(
    clientId: Option[UUID],
    subject: => String
  ): ValidatedNel[ClientAssertionValidationError, UUID] =
    Try(Option(subject)).flatMap(_.traverse(_.toUUID)) match {
      case Failure(_)                                     => InvalidSubjectFormat(Try(subject).getOrElse("")).invalidNel
      case Success(None)                                  => SubjectNotFound.invalidNel
      case Success(Some(s)) if s == clientId.getOrElse(s) => s.validNel
      case Success(Some(s))                               => InvalidSubject(s.toString).invalidNel
    }

  protected def purposeIdClaim(purposeId: => String): ValidatedNel[ClientAssertionValidationError, Option[UUID]] =
    Try(Option(purposeId))
      .flatMap(_.traverse(_.toUUID))
      .toEither
      .leftMap(_ => InvalidPurposeIdFormat(Option(purposeId).getOrElse("")))
      .toValidatedNel

  private def audience(
    receivedAudiences: Set[String],
    expectedAudiences: Set[String]
  ): ValidatedNel[ClientAssertionValidationError, Set[String]] =
    Either
      .cond(
        receivedAudiences.intersect(expectedAudiences).nonEmpty,
        receivedAudiences,
        InvalidAudiences(receivedAudiences)
      )
      .toValidatedNel

  private def digestClaim(claimSet: JWTClaimsSet): ValidatedNel[ClientAssertionValidationError, Option[Digest]] = {
    val found: Option[Map[String, AnyRef]] = Option(claimSet.getJSONObjectClaim(DIGEST_CLAIM)).map(_.asScala.toMap)
    found.traverse(rawDigest => extractDigestClaimsNumber(rawDigest).flatMap(verifyDigestLength)).toValidatedNel
  }

  private def extractDigestClaimsNumber(
    rawDigest: Map[String, AnyRef]
  ): Either[ClientAssertionValidationError, Digest] =
    if (rawDigest.keySet.size == 2) Digest.create(rawDigest)
    else Left(InvalidDigestClaims)

  private def verifyDigestLength(digest: Digest): Either[ClientAssertionValidationError, Digest] = digest.alg match {
    case SHA_256 if digest.value.length == 64 => Right(digest)
    case SHA_256                              => Left(InvalidHashLength(SHA_256))
    case _                                    => Left(InvalidHashAlgorithm)
  }

}
