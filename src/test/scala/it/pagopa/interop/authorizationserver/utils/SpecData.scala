package it.pagopa.interop.authorizationserver.utils

import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.authorizationserver.model.{ClientAssertionDetails, JWTDetailsMessage}
import it.pagopa.interop.commons.jwt.JWTConfiguration
import it.pagopa.interop.commons.jwt.model.Token

import java.time.{OffsetDateTime, ZoneOffset}
import java.util.UUID

object SpecData {
  val timestamp: OffsetDateTime = OffsetDateTime.of(2022, 12, 31, 11, 22, 33, 44, ZoneOffset.UTC)

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
    "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxQ0kxRENEWE9VaWtZbTJhdVFWNwpDcmdJbjNyM2FQeE1wMFdiTjNiamZBZFNsc3AzR1o0dUJVK3F5SGVQNUF0RVZxVW9ZaUNRaForcFo3T1F5bUxQCllibHVIK3h2dWpBVUxVS3VOWi85RlhtQXU4S2VMV09TUGhDWDFkeUhSRFhJZit3QWZzZVZxU2VLTElzeUhqcTkKWXF3WUFONWYvTGdzVlA4UUpLdnhZSEtXWW5hRTVKa1lESkIwT25hZjU0U1BWRU9PNUxqczJ0bDAwLzBNeTlvSApwWjV6c2dpcjRoSlZvNEJGb3hPSzhlcTQxTzJGYlpXQWlIbTBvbFpMeG0vU3dRbXNWNGpETmNQQis4ZE1UdFFXCjg0dGtYNUZyOEpwbFRMZkxUSm1FNGJTcTJUZnAvb2czeGNxM0dpeDZGVm56RWNIMmZkbXk3STgyR3J6dURJOWIKZndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
  val validClientAssertion     =
    "eyJraWQiOiJLZDNXUkFEaTV5akM1eTdVeDczTG5rOWN2c0w1aE1IcGxVdXE1eUtzQk1nIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIzZGEyYzk1NS1mY2FlLTQ1N2YtOTI2Zi02ZGM0MWI4Zjk1YTkiLCJhdWQiOiJ0ZXN0LmludGVyb3AucGFnb3BhLml0IiwibmJmIjoxNjUwNjIxODU5LCJpc3MiOiIzZGEyYzk1NS1mY2FlLTQ1N2YtOTI2Zi02ZGM0MWI4Zjk1YTkiLCJwdXJwb3NlSWQiOiJiNTQwYTQxNS1mNjVkLTQyNzAtOWJhZC03Yjc4OWQxMjQxNzYiLCJleHAiOjQxMDIzNTQ4MDAsImlhdCI6MTY1MDYyMTg1OSwianRpIjoiOGUwYWQ5YjItODc4OC00NTgxLWEwZjUtZDMyNjAxOGI5YzNhIn0.htnYZhRHcSZUvPYLS1bEgidjymZJJ4hj0FudC374oFupjdIF2xVVW9DZrFYaeiUKr9rANCrUkSmRHKeQcQ0OofJI_dha2v7C6DdTLkiMhAr6imGQEwU3vu75bdnLcOmVeq4KKAmDA6YW6ApKpd5rgNjwzfNEVBsYFW2e0v85ZaovQO36Cr8jjC04kMV8GiHA6Jonu9TfW7Vz7tVayOaI6Eg1CnCPa2lqRM30OJG03GwmtCSWlkOTPDqdpF1GI71xrg9wbczCmw5BvzBRISHpwPluqPOpxqn6Nf9Xo8DNHDaE8ZfH48Uy1T0qPsrH0Awsh8PYXgGXlp12tZbLszhaaQ"
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
      "qCI1DCDXOUikYm2auQV7CrgIn3r3aPxMp0WbN3bjfAdSlsp3GZ4uBU-qyHeP5AtEVqUoYiCQhZ-pZ7OQymLPYbluH-xvujAULUKuNZ_9FXmAu8KeLWOSPhCX1dyHRDXIf-wAfseVqSeKLIsyHjq9YqwYAN5f_LgsVP8QJKvxYHKWYnaE5JkYDJB0Onaf54SPVEOO5Ljs2tl00_0My9oHpZ5zsgir4hJVo4BFoxOK8eq41O2FbZWAiHm0olZLxm_SwQmsV4jDNcPB-8dMTtQW84tkX5Fr8JplTLfLTJmE4bSq2Tfp_og3xcq3Gix6FVnzEcH2fdmy7I82GrzuDI9bfw"
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
