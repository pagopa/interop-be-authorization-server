package it.pagopa.interop.authorizationserver.utils

import cats.implicits.catsSyntaxOptionId
import it.pagopa.interop.authorizationmanagement.client.model.{Client, ClientComponentState, ClientKind, KeyWithClient}
import it.pagopa.interop.authorizationserver.model.{ClientAssertionDetails, JWTDetailsMessage}
import it.pagopa.interop.clientassertionvalidation.SpecData.{makeClient, rsaKey, rsaKid}
import it.pagopa.interop.clientassertionvalidation.SpecUtil.{fastClientAssertionJWT, keyFromRSAKey}
import it.pagopa.interop.commons.jwt.model.Token
import it.pagopa.interop.commons.utils.PURPOSE_ID_CLAIM

import java.time.{OffsetDateTime, ZoneOffset}
import java.util.{Date, UUID}

object SpecData {
  val correlationId: String = UUID.randomUUID().toString
  final val timestamp       = OffsetDateTime.of(2022, 12, 31, 11, 22, 33, 44, ZoneOffset.UTC)

  val clientId: UUID             = UUID.randomUUID()
  val purposeId: UUID            = UUID.randomUUID()
  val clientAssertionJti: String = UUID.randomUUID().toString
  val clientAssertionIssuedAt    = 1650621859L
  val clientAssertionExpiresAt   = 4102354800L
  val clientAssertionAudience    = "test.interop.pagopa.it"
  val clientAssertionAlgorithm   = "RS256"

  val validClientAssertion: String = fastClientAssertionJWT(
    issuer = clientId.toString.some,
    subject = clientId.toString.some,
    jti = clientAssertionJti.some,
    iat = new Date(clientAssertionIssuedAt * 1000).some,
    expirationTime = new Date(clientAssertionExpiresAt * 1000).some,
    audience = List(clientAssertionAudience),
    customClaims = Map(PURPOSE_ID_CLAIM -> purposeId.toString),
    algorithm = clientAssertionAlgorithm.some
  )

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

  val activeClient: Client = makeClient(
    purposeState = ClientComponentState.ACTIVE,
    eServiceState = ClientComponentState.ACTIVE,
    agreementState = ClientComponentState.ACTIVE,
    kind = ClientKind.CONSUMER,
    purposeId = purposeId
  ).copy(id = clientId)

  val expectedQueueMessage: JWTDetailsMessage = JWTDetailsMessage(
    jwtId = generatedToken.jti,
    correlationId = Some(correlationId),
    issuedAt = generatedToken.iat * 1000,
    clientId = clientId.toString,
    organizationId = activeClient.consumerId.toString,
    agreementId = activeClient.purposes.head.states.agreement.agreementId.toString,
    eserviceId = activeClient.purposes.head.states.eservice.eserviceId.toString,
    descriptorId = activeClient.purposes.head.states.eservice.descriptorId.toString,
    purposeId = purposeId.toString,
    purposeVersionId = activeClient.purposes.head.states.purpose.versionId.toString,
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
      keyId = rsaKid,
      issuer = clientId.toString,
      subject = clientId.toString,
      audience = clientAssertionAudience,
      expirationTime = clientAssertionExpiresAt * 1000
    )
  )

  val localKeyWithClient: KeyWithClient = KeyWithClient(key = keyFromRSAKey(rsaKid, rsaKey), client = activeClient)

}
