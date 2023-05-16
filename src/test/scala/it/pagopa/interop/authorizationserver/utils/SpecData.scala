package it.pagopa.interop.authorizationserver.utils

import it.pagopa.interop.authorizationserver.model.{ClientAssertionDetails, JWTDetailsMessage}
import it.pagopa.interop.clientassertionvalidation.SpecData._
import it.pagopa.interop.commons.jwt.model.Token

import java.time.{OffsetDateTime, ZoneOffset}
import java.util.UUID

object SpecData {
  val correlationId: String = UUID.randomUUID().toString
  final val timestamp       = OffsetDateTime.of(2022, 12, 31, 11, 22, 33, 44, ZoneOffset.UTC)

  val generatedToken: Token = Token(
    serialized = "generated-jwt",
    jti = "qwerty",
    iat = 0,
    exp = 100,
    nbf = 0,
    expIn = 100,
    alg = "alg",
    kid = "kid",
    aud = List("aud"),
    sub = "sub",
    iss = "iss"
  )

  val expectedQueueMessage: JWTDetailsMessage = JWTDetailsMessage(
    jwtId = generatedToken.jti,
    correlationId = Some(correlationId),
    issuedAt = generatedToken.iat * 1000,
    clientId = clientId.toString,
    organizationId = consumerId.toString,
    agreementId = agreementId.toString,
    eserviceId = eServiceId.toString,
    descriptorId = descriptorId.toString,
    purposeId = purposeId.toString,
    purposeVersionId = purposeVersionId.toString,
    algorithm = generatedToken.alg,
    keyId = generatedToken.kid,
    audience = generatedToken.aud.mkString(","),
    subject = generatedToken.sub,
    notBefore = generatedToken.nbf * 1000,
    expirationTime = generatedToken.exp * 1000,
    issuer = generatedToken.iss,
    clientAssertion = ClientAssertionDetails(
      jwtId = clientAssertionJti,
      issuedAt = clientAssertionIssuedAt * 1000,
      algorithm = clientAssertionAlgorithm,
      keyId = clientAssertionKid,
      issuer = clientId.toString,
      subject = clientId.toString,
      audience = clientAssertionAudience,
      expirationTime = clientAssertionExpiresAt * 1000
    )
  )

}
