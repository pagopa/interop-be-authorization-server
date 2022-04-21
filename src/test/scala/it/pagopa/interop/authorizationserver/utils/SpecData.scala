package it.pagopa.interop.authorizationserver.utils

import it.pagopa.interop.authorizationmanagement.client.model.{
  Client,
  ClientAgreementDetails,
  ClientComponentState,
  ClientEServiceDetails,
  ClientKey,
  ClientKind,
  ClientPurposeDetails,
  ClientStatesChain,
  Key,
  Purpose
}
import it.pagopa.interop.authorizationserver.model.{ClientCredentialsResponse, JWTDetailsMessage, TokenType}
import it.pagopa.interop.commons.jwt.model.Token

import java.time.OffsetDateTime
import java.util.UUID

object SpecData {
  val internalToken: Token  = Token(serialized = "internal-jwt", jti = "internal-jti", iat = 0, exp = 100, nbf = 0)
  val generatedToken: Token = Token(serialized = "generated-jwt", jti = "qwerty", iat = 0, exp = 100, nbf = 0)

  val clientId: UUID   = UUID.randomUUID()
  val purposeId: UUID  = UUID.randomUUID()
  val consumerId: UUID = UUID.randomUUID()
  val eServiceId: UUID = UUID.randomUUID()

  val clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  val grantType           = "client_credentials"

  val kid = "kid"

  val eServiceAudience      = "e-service-audience"
  val eServiceTokenDuration = 100

  val clientAssertion = "client-assertion"

  val clientKey: ClientKey = ClientKey(
    key = Key(kty = "kty", kid = kid),
    relationshipId = UUID.randomUUID(),
    name = "keyName",
    createdAt = OffsetDateTime.now()
  )

  val activeClient: Client = Client(
    id = clientId,
    consumerId = consumerId,
    name = "clientName",
    description = None,
    purposes = Seq(
      Purpose(
        purposeId = purposeId,
        states = ClientStatesChain(
          id = UUID.randomUUID(),
          eservice = ClientEServiceDetails(
            eserviceId = eServiceId,
            state = ClientComponentState.ACTIVE,
            audience = Seq(eServiceAudience),
            voucherLifespan = eServiceTokenDuration
          ),
          agreement = ClientAgreementDetails(
            eserviceId = eServiceId,
            consumerId = consumerId,
            state = ClientComponentState.ACTIVE
          ),
          purpose = ClientPurposeDetails(purposeId = purposeId, state = ClientComponentState.ACTIVE)
        )
      )
    ),
    relationships = Set.empty,
    kind = ClientKind.CONSUMER
  )

  val expectedQueueMessage: JWTDetailsMessage = JWTDetailsMessage(
    jti = generatedToken.jti,
    iat = generatedToken.iat,
    exp = generatedToken.exp,
    clientId = clientId.toString,
    purposeId = Some(purposeId.toString),
    kid = kid
  )

  val expectedResponse: ClientCredentialsResponse =
    ClientCredentialsResponse(
      generatedToken.serialized,
      TokenType.Bearer,
      generatedToken.exp.toInt // TODO Check this (expires_in or expires_at?)
    )
}
