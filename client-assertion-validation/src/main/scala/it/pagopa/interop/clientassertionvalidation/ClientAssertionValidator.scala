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
import it.pagopa.interop.clientassertionvalidation.utils.ValidationTypes._
import it.pagopa.interop.commons.utils.TypeConversions._
import it.pagopa.interop.commons.utils.{DIGEST_CLAIM, PURPOSE_ID_CLAIM}

import java.net.URLEncoder
import java.util.UUID
import scala.jdk.CollectionConverters._
import scala.util.{Failure, Success, Try}

trait ClientAssertionValidator {
  def validateClientAssertion(
    clientAssertionJws: String,
    clientId: Option[UUID]
  ): Either[NonEmptyList[ValidationFailure], AssertionValidationResult]

  def verifySignature(
    validationResult: AssertionValidationResult,
    publicKey: String
  ): Either[SignatureVerificationFailure, Unit]
}

final class NimbusClientAssertionValidator(expectedAudience: Set[String]) extends ClientAssertionValidator {
  private val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
    new DefaultJWTClaimsVerifier[SecurityContext](null, null, null, null)

  val SHA_256: String           = "SHA256"
  val ALLOWED_ALGORITHM: String = "RS256"

  override def validateClientAssertion(
    clientAssertionJws: String,
    clientId: Option[UUID]
  ): Either[NonEmptyList[ValidationFailure], AssertionValidationResult] =
    for {
      jwt             <- parseClientAssertion(clientAssertionJws)
      clientAssertion <- verifyClaims(jwt, clientId, clientAssertionJws)
    } yield AssertionValidationResult(clientAssertion, jwt)

  override def verifySignature(
    validationResult: AssertionValidationResult,
    publicKey: String
  ): Either[SignatureVerificationFailure, Unit] =
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
  ): Either[NonEmptyList[ValidationFailure], ClientAssertion] =
    for {
      claimSet        <- validateStandardClaims(jwt)
      clientAssertion <- (
        kidHeader(jwt.getHeader.getKeyID),
        algorithm(jwt.getHeader.getAlgorithm.getName),
        subjectClaim(clientId, claimSet.getSubject),
        purposeIdClaim(claimSet.getStringClaim(PURPOSE_ID_CLAIM)),
        getOrFail(claimSet.getJWTID, JtiNotFound),
        getOrFail(claimSet.getIssueTime.getTime, IssuedAtNotFound),
        getOrFail(claimSet.getIssuer, IssuerNotFound),
        audience(claimSet.getAudience.asScala.toSet, expectedAudience),
        getOrFail(claimSet.getExpirationTime.getTime, ExpirationNotFound),
        digestClaim(claimSet)
      ).tupled.map { case (kid, algorithm, subject, purposeId, jti, issuedAt, issuer, audience, expiration, digest) =>
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

    } yield clientAssertion

  private def parseClientAssertion(clientAssertion: String): Either[NonEmptyList[ValidationFailure], SignedJWT] =
    Try(SignedJWT.parse(clientAssertion)).toEither.leftMap(ex =>
      NonEmptyList.one(ClientAssertionParseFailed(ex.getMessage))
    )

  private def validateStandardClaims(jwt: SignedJWT): Either[NonEmptyList[ClientAssertionInvalidClaims], JWTClaimsSet] =
    (
      for {
        claimSet <- Try(jwt.getJWTClaimsSet)
        _        <- Try(claimsVerifier.verify(claimSet, null))
      } yield claimSet
    ).toEither
      .leftMap(ex => NonEmptyList.one(ClientAssertionInvalidClaims(ex.getMessage)))

  private def getOrFail[E, T](value: => T, error: => E): ValidatedNel[E, T] =
    Try(Option(value)) match {
      case Failure(_) | Success(None)                 => error.invalidNel
      case Success(v) if v.exists(_.toString.isBlank) => error.invalidNel
      case Success(Some(v))                           => v.validNel
    }

  private def rsaVerifier(publicKeyJwk: String): Either[PublicKeyParseFailed, RSASSAVerifier] = Try {
    val jwk: JWK  = JWK.parse(publicKeyJwk)
    val publicKey = jwk.toRSAKey
    new RSASSAVerifier(publicKey)
  }.toEither.leftMap(ex => PublicKeyParseFailed(ex.getMessage))

  private def subjectClaim(clientId: Option[UUID], subject: => String): ValidatedNel[ValidationFailure, UUID] =
    Try(Option(subject)).flatMap(_.traverse(_.toUUID)) match {
      case Failure(_)                                     => InvalidSubjectFormat(Try(subject).getOrElse("")).invalidNel
      case Success(None)                                  => SubjectNotFound.invalidNel
      case Success(Some(s)) if s == clientId.getOrElse(s) => s.validNel
      case Success(Some(s))                               => InvalidSubject(s.toString).invalidNel
    }

  protected def purposeIdClaim(purposeId: => String): ValidatedNel[ValidationFailure, Option[UUID]] = {
    val result =
      for {
        maybePurposeId   <- Try(Option(purposeId)).toEither.leftMap(ex => InvalidPurposeIdClaimFormat(ex.getMessage))
        maybePurposeUuid <- maybePurposeId.traverse(pId =>
          pId.toUUID.toEither.leftMap(_ => InvalidPurposeIdFormat(pId))
        )
      } yield maybePurposeUuid

    result.toValidatedNel
  }

  protected def kidHeader(kid: => String): ValidatedNel[ValidationFailure, String] =
    getOrFail(kid, KidNotFound).andThen { k =>
      // Verify that kid does not contain special characters
      if (k == URLEncoder.encode(k, "UTF-8")) k.validNel
      else InvalidKidFormat.invalidNel
    }

  private def audience(
    receivedAudiences: => Set[String],
    expectedAudiences: Set[String]
  ): ValidatedNel[ValidationFailure, Set[String]] = {
    val result = for {
      audiences <- Try(receivedAudiences).toEither.leftMap(ex => InvalidAudienceFormat(ex.getMessage))
      _ <- Left(InvalidAudiences(audiences)).withRight[Unit].unlessA(audiences.intersect(expectedAudiences).nonEmpty)
    } yield audiences

    result.toValidatedNel
  }

  private def algorithm(alg: => String): ValidatedNel[ValidationFailure, String] =
    getOrFail(alg, AlgorithmNotFound).andThen(a =>
      if (a == ALLOWED_ALGORITHM) a.validNel else AlgorithmNotAllowed(a).invalidNel
    )

  private def digestClaim(claimSet: JWTClaimsSet): ValidatedNel[ValidationFailure, Option[Digest]] = {
    val result = for {
      maybeDigestClaim <- Try(Option(claimSet.getJSONObjectClaim(DIGEST_CLAIM)).map(_.asScala.toMap)).toEither.leftMap(
        ex => InvalidDigestFormat(ex.getMessage)
      )
      maybeDigest      <- maybeDigestClaim.traverse(rawDigest =>
        extractDigestClaimsNumber(rawDigest).flatMap(verifyDigestLength)
      )
    } yield maybeDigest

    result.toValidatedNel
  }

  private def extractDigestClaimsNumber(rawDigest: Map[String, AnyRef]): Either[ValidationFailure, Digest] =
    if (rawDigest.keySet.size == 2) Digest.create(rawDigest)
    else Left(InvalidDigestClaims)

  private def verifyDigestLength(digest: Digest): Either[ValidationFailure, Digest] = digest.alg match {
    case SHA_256 if digest.value.length == 64 => Right(digest)
    case SHA_256                              => Left(InvalidHashLength(SHA_256))
    case _                                    => Left(InvalidHashAlgorithm)
  }

}
