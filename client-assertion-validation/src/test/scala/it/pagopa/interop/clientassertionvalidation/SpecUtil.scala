package it.pagopa.interop.clientassertionvalidation

import cats.syntax.all._
import com.nimbusds.jose.crypto.{ECDSASigner, RSASSASigner}
import com.nimbusds.jose.jwk.{JWK, RSAKey}
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import it.pagopa.interop.authorizationmanagement.client.model.{JWKKey, OtherPrimeInfo}
import it.pagopa.interop.clientassertionvalidation.SpecData._

import java.util.{Date, UUID}
import scala.jdk.CollectionConverters._
object SpecUtil {

  val jwtValidator: ClientAssertionValidator =
    new NimbusClientAssertionValidator(Set(SpecData.clientAssertionAudience))

  def fastClientAssertionJWT(
    issuer: Option[String] = clientId.toString.some,
    subject: Option[String] = clientId.toString.some,
    audience: List[String] = List(clientAssertionAudience),
    expirationTime: Option[Date] = assertionExpirationTime.some,
    algorithm: Option[String] = clientAssertionAlgorithm.some,
    kid: Option[String] = rsaKid.some,
    privateKeyPEM: Option[String] = rsaPrivateKey.some,
    jti: Option[String] = UUID.randomUUID.toString.some,
    iat: Option[Date] = new Date().some,
    customClaims: Map[String, AnyRef] = Map.empty
  ): String =
    makeClientAssertionJWT(
      issuer,
      subject,
      audience,
      expirationTime,
      algorithm,
      kid,
      privateKeyPEM,
      jti,
      iat,
      customClaims
    )

  def makeClientAssertionJWT(
    issuer: Option[String],
    subject: Option[String],
    audience: List[String],
    expirationTime: Option[Date],
    algorithm: Option[String],
    kid: Option[String],
    privateKeyPEM: Option[String],
    jti: Option[String],
    iat: Option[Date],
    customClaims: Map[String, AnyRef] = Map.empty
  ): String = {
    val now = new Date()
    val jwk = JWK.parse(privateKeyPEM.orNull)

    // Quick and dirty
    val signer =
      if (algorithm.getOrElse("RS256").startsWith("RS")) new RSASSASigner(jwk.toRSAKey.toPrivateKey)
      else new ECDSASigner(jwk.toECKey)

    val tempClaimsSet = new JWTClaimsSet.Builder()
      .issuer(issuer.orNull)
      .subject(subject.orNull)
      .jwtID(jti.orNull)
      .audience(audience.asJava)
      .expirationTime(expirationTime.orNull)
      .issueTime(iat.orNull)
      .notBeforeTime(now)

    customClaims.map { case (k, v) => tempClaimsSet.claim(k, v) }

    val claimsSet = tempClaimsSet.build()
    val alg       = algorithm.map(JWSAlgorithm.parse)

    val jwsObject = new SignedJWT(
      new JWSHeader.Builder(alg.orNull)
        .keyID(kid.orNull)
        .build,
      claimsSet
    )

    jwsObject.sign(signer)
    jwsObject.serialize
  }

  def keyFromRSAKey(kid: String, key: RSAKey): JWKKey = {
    val otherPrimes = Option(key.getOtherPrimes)
      .map(list =>
        list.asScala
          .map(entry =>
            OtherPrimeInfo(
              r = entry.getPrimeFactor.toString,
              d = entry.getFactorCRTExponent.toString,
              t = entry.getFactorCRTCoefficient.toString
            )
          )
          .toSeq
      )
      .filter(_.nonEmpty)

    JWKKey(
      use = None,
      alg = None,
      kty = key.getKeyType.getValue,
      keyOps = Option(key.getKeyOperations).map(list => list.asScala.map(op => op.toString).toSeq),
      kid = kid,
      x5u = Option(key.getX509CertURL).map(_.toString),
      x5t = getX5T(key),
      x5tS256 = Option(key.getX509CertSHA256Thumbprint).map(_.toString),
      x5c = Option(key.getX509CertChain).map(list => list.asScala.map(op => op.toString).toSeq),
      crv = None,
      x = None,
      y = None,
      d = Option(key.getPrivateExponent).map(_.toString),
      k = None,
      n = Option(key.getModulus).map(_.toString),
      e = Option(key.getPublicExponent).map(_.toString),
      p = Option(key.getFirstPrimeFactor).map(_.toString),
      q = Option(key.getSecondPrimeFactor).map(_.toString),
      dp = Option(key.getFirstFactorCRTExponent).map(_.toString),
      dq = Option(key.getSecondFactorCRTExponent).map(_.toString),
      qi = Option(key.getFirstCRTCoefficient).map(_.toString),
      oth = otherPrimes
    )
  }

  private def getX5T(key: JWK): Option[String] = Option(key.getX509CertSHA256Thumbprint).map(_.toString)
}
