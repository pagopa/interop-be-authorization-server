package it.pagopa.interop.authorizationserver.utils

import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.authorizationserver.model.{ClientAssertionDetails, JWTDetailsMessage}
import it.pagopa.interop.commons.jwt.JWTConfiguration
import it.pagopa.interop.commons.jwt.model.Token
import java.time.{OffsetDateTime, ZoneOffset}

import java.util.UUID

object SpecData {
  val correlationId: String = UUID.randomUUID().toString
  final val timestamp       = OffsetDateTime.of(2022, 12, 31, 11, 22, 33, 44, ZoneOffset.UTC)

  val internalToken: Token  = Token(
    serialized = "internal-jwt",
    jti = "internal-jti",
    iat = 0,
    exp = 100,
    nbf = 0,
    expIn = JWTConfiguration.jwtInternalTokenConfig.durationInSeconds,
    alg = "alg",
    kid = "kid",
    aud = List("aud"),
    sub = "sub",
    iss = "iss"
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

  val consumerId: UUID       = UUID.randomUUID()
  val eServiceId: UUID       = UUID.randomUUID()
  val descriptorId: UUID     = UUID.randomUUID()
  val agreementId: UUID      = UUID.randomUUID()
  val purposeVersionId: UUID = UUID.randomUUID()

  val clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  val grantType           = "client_credentials"

  // These values have been used to generate test tokens.
  //   Any change to them would probably require to re-generate tokens and keys.
  //   Do not change these values if you are not sure
  val clientId: UUID           = UUID.fromString("3da2c955-fcae-457f-926f-6dc41b8f95a9")
  val purposeId: UUID          = UUID.fromString("b540a415-f65d-4270-9bad-7b789d124176")
  val clientAssertionJti       = "8e0ad9b2-8788-4581-a0f5-d326018b9c3a"
  val clientAssertionKid       = "Kd3WRADi5yjC5y7Ux73Lnk9cvsL5hMHplUuq5yKsBMg"
  val clientAssertionIssuedAt  = 1650621859L
  val clientAssertionExpiresAt = 4102354800L
  val clientAssertionAlgorithm = "RS256"
  val clientAssertionAudience  = "test.interop.pagopa.it"
  val validPublicKey           =
    "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4N1JhUFpiTXR1RUhZYk9pOGcvaQpXL1RXYkJ5ZDBVWG5uU1NWbnFqQWdMU2lNbG05U2o1eE9hamNYZ0lnenJ4SGJBa1g3ak5lbXpMRWo3WXFqaEg4CkZBT0svUXI1OG1JT0FENzFCYjRWd3lsY2Rlc2dCclBJeGxTdDhlZmViWDllQy9wa3pudC9oRGlXWHN0d24xcW4KM1p5OUhRcC9lK0VWeC94aDRBalZ0S214eS90ekYxT2xLTWNXdnMwZmhZUCtSOXVKWGpPWm9kR0xkU1ZlYzgzaQoxWXIwK1VqVmdxbCtOSEpBUjFHaDJ2K2d5UzBQbHRQMGMzVTdYSFRBUk9MblR1UXVOaEp0OGR4ZjFjV1lPcVZhCkk0Tm9RNzRoVkdaazRLWU5qWTNpamVEMERlamtUVmNQSE5WWFd2bTZwWUN5Sy80NXhuMU42VlNlTldnNVV2dzUKK3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
  val validClientAssertion     =
    "eyJraWQiOiJLZDNXUkFEaTV5akM1eTdVeDczTG5rOWN2c0w1aE1IcGxVdXE1eUtzQk1nIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIzZGEyYzk1NS1mY2FlLTQ1N2YtOTI2Zi02ZGM0MWI4Zjk1YTkiLCJhdWQiOiJ0ZXN0LmludGVyb3AucGFnb3BhLml0IiwibmJmIjoxNjUwNjIxODU5LCJpc3MiOiIzZGEyYzk1NS1mY2FlLTQ1N2YtOTI2Zi02ZGM0MWI4Zjk1YTkiLCJwdXJwb3NlSWQiOiJiNTQwYTQxNS1mNjVkLTQyNzAtOWJhZC03Yjc4OWQxMjQxNzYiLCJleHAiOjQxMDIzNTQ4MDAsImlhdCI6MTY1MDYyMTg1OSwianRpIjoiOGUwYWQ5YjItODc4OC00NTgxLWEwZjUtZDMyNjAxOGI5YzNhIn0.edMcvgVUnomVzKKAc0pT0HXPOOKdd060MFQvCJDzEOUlJErUmt1rAlrvNraT-83qhbNXA6LHMZ-vfFtDD_Zu6lEBfXFQg29kZMQcQ-N2JzuL4J8LiqTHKQaf49BB8rbnvZezQjG552t-mdUy8j2XI_aKJQJc5kXCWPqC0cwiklUjMkfWgYciBFVHfzMGhQD7yQIT4YzjPg-jYp5iVlv9eTVc1WXgfllv7btqyHtfplK7EH-5wDTLSmOFrqxu2eTJ6qEKBpc6K2Nu9n-IKvbdfWhyoPUdIdyi-juTPT_sCDak2R5UYOlF9jgzktpHd6rj1mCfYlA26UoDGX1dgpzx2g"
  val modelKey: Key            = Key(
    kty = "RSA",
    keyOps = None,
    use = Some("sig"),
    alg = Some("RS256"),
    kid = "NCapnP1ppEJkFXHYFQGtBf6C-_dUU3XfGVyA4-uKaMo",
    x5u = None,
    x5t = None,
    x5tS256 = None,
    x5c = None,
    crv = None,
    x = None,
    y = None,
    d = None,
    k = None,
    n = Some(
      "x7RaPZbMtuEHYbOi8g_iW_TWbByd0UXnnSSVnqjAgLSiMlm9Sj5xOajcXgIgzrxHbAkX7jNemzLEj7YqjhH8FAOK_Qr58mIOAD71Bb4VwylcdesgBrPIxlSt8efebX9eC_pkznt_hDiWXstwn1qn3Zy9HQp_e-EVx_xh4AjVtKmxy_tzF1OlKMcWvs0fhYP-R9uJXjOZodGLdSVec83i1Yr0-UjVgql-NHJAR1Gh2v-gyS0PltP0c3U7XHTAROLnTuQuNhJt8dxf1cWYOqVaI4NoQ74hVGZk4KYNjY3ijeD0DejkTVcPHNVXWvm6pYCyK_45xn1N6VSeNWg5Uvw5-w"
    ),
    e = Some("AQAB"),
    p = None,
    q = None,
    dp = None,
    dq = None,
    qi = None,
    oth = None
  )
  // ------------------------------------

  val clientAssertionWithWrongSubject =
    "eyJraWQiOiJLZDNXUkFEaTV5akM1eTdVeDczTG5rOWN2c0w1aE1IcGxVdXE1eUtzQk1nIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJkZWZpbml0ZWx5LW5vdC1hbi11dWlkIiwiYXVkIjoidGVzdC5pbnRlcm9wLnBhZ29wYS5pdCIsIm5iZiI6MTY1MDYyMTg1OSwiaXNzIjoiM2RhMmM5NTUtZmNhZS00NTdmLTkyNmYtNmRjNDFiOGY5NWE5IiwicHVycG9zZUlkIjoiYjU0MGE0MTUtZjY1ZC00MjcwLTliYWQtN2I3ODlkMTI0MTc2IiwiZXhwIjo0MTAyMzU0ODAwLCJpYXQiOjE2NTA2MjE4NTksImp0aSI6IjhlMGFkOWIyLTg3ODgtNDU4MS1hMGY1LWQzMjYwMThiOWMzYSJ9.GI_5X1NSGn3huiWueli107cgcrvJYUYs3eQWrNKGJCbPea0ncqHLkP0_vhZxqhMMaOZfQqxydJumOLfeqgLUFaPB0a7FCOqEf3VCnb-cFetarryVvaGuYQr_Rs9OP5482TRMEJECeURRT_3ix03uEMzESjuVQMBcOrw8WDo6WYEmAJRpk1monZk-zNe_8wCUoNHNH_MLrBXw4UeTAZFT-NI8RoT0zd7nWbENzDrBGCpernHqXR_mS4ypgeQsHdUhP5oOXa-wCa8P3lskwgVU3nMMA3x6yEPY4E5xDASCUw2l677JFquLAIMsCV_2c4m0Cr11Vs6m96FQ24ty8a6Q4w"

  val clientAssertionWithWrongPurposeId =
    "eyJraWQiOiJLZDNXUkFEaTV5akM1eTdVeDczTG5rOWN2c0w1aE1IcGxVdXE1eUtzQk1nIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIzZGEyYzk1NS1mY2FlLTQ1N2YtOTI2Zi02ZGM0MWI4Zjk1YTkiLCJhdWQiOiJ0ZXN0LmludGVyb3AucGFnb3BhLml0IiwibmJmIjoxNjUwNjIxODU5LCJpc3MiOiIzZGEyYzk1NS1mY2FlLTQ1N2YtOTI2Zi02ZGM0MWI4Zjk1YTkiLCJwdXJwb3NlSWQiOiJkZWZpbml0ZWx5LW5vdC1hbi11dWlkIiwiZXhwIjo0MTAyMzU0ODAwLCJpYXQiOjE2NTA2MjE4NTksImp0aSI6IjhlMGFkOWIyLTg3ODgtNDU4MS1hMGY1LWQzMjYwMThiOWMzYSJ9.R1QHteRIUwzxp_t5PYNd8LnwrQ_XQaEEVzP7TrqVBQiVDg8cINPGkRLtH0qTTZLOHRdLbC-3VSxaH3Vma0WzxBZfXkON_JMgb-1DK3gtB3rcgYZoGkfDxUWLUt0LOzRE9vByebY4Bkx0-XIPE7iXjv255w3bo0Bpaiq9UdOZeCwv_rJW2w-qPTOLzUyVJeWEYzbC0VGFnOkn57Nw03spYMQrY0kg7H1S8lhUbKVJwG4VY7wLkJO5Nb2USrwzJwwCCpKq9wPQIb57yrpbYoyi1hvLwhSbJ8LiDByrBTojIgeepmBjt6DKzsXAmoicAMnfH4AktSxQSLlA3u-ZJKaBKA"

  val eServiceAudience      = "e-service-audience"
  val eServiceTokenDuration = 100

  val anotherModelKey: Key = modelKey.copy(n =
    Some(
      "oWHaq1cUlIUM1kvzJABltbilH_UtVHXVDSyUOLiVNffGpguOGj6ngW6ExYZX-3vnXYZ27LRFBxydA912yG3WsPy412MNdUT0h6yMVkju3212OMsMWIO5b1Sp9jxpQqKtpjvzYM5Bh-mFWjug3WVnwY8rjiWx3XnNudLgjSZxteprvQ4GCAmYCiiq6t2D-_0nwvmi162ySGtLXEzRUEL-AkwzS0UV0uNzvFxqkuAPvEAOmb28yqKgmHQnQwf3t9NsS3pqV1OaHmfQeeWQeVhPOfzAFsZhOH0GqZwPTCP2_Z9zp9HIdfVgUa4yvFfKo48QfePTT8Dy8xM9bhuAu0gdgw"
    )
  )

  def makeClient(
    purposeState: ClientComponentState = ClientComponentState.ACTIVE,
    eServiceState: ClientComponentState = ClientComponentState.ACTIVE,
    agreementState: ClientComponentState = ClientComponentState.ACTIVE,
    kind: ClientKind = ClientKind.CONSUMER
  ): Client = Client(
    id = clientId,
    consumerId = consumerId,
    name = "clientName",
    description = None,
    purposes = Seq(
      Purpose(states =
        ClientStatesChain(
          id = UUID.randomUUID(),
          eservice = ClientEServiceDetails(
            eserviceId = eServiceId,
            descriptorId = descriptorId,
            state = eServiceState,
            audience = Seq(eServiceAudience),
            voucherLifespan = eServiceTokenDuration
          ),
          agreement = ClientAgreementDetails(
            eserviceId = eServiceId,
            consumerId = consumerId,
            agreementId = agreementId,
            state = agreementState
          ),
          purpose = ClientPurposeDetails(purposeId = purposeId, versionId = purposeVersionId, state = purposeState)
        )
      )
    ),
    relationships = Set.empty,
    createdAt = timestamp,
    kind = kind
  )

  val activeClient: Client = makeClient(
    purposeState = ClientComponentState.ACTIVE,
    eServiceState = ClientComponentState.ACTIVE,
    agreementState = ClientComponentState.ACTIVE,
    kind = ClientKind.CONSUMER
  )

  val keyWithClient: KeyWithClient = KeyWithClient(key = modelKey, client = activeClient)

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
