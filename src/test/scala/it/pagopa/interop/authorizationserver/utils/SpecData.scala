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

  val consumerId: UUID = UUID.randomUUID()
  val eServiceId: UUID = UUID.randomUUID()

  val clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  val grantType           = "client_credentials"

  // Do not change these values
  val clientId: UUID       = UUID.fromString("3da2c955-fcae-457f-926f-6dc41b8f95a9")
  val purposeId: UUID      = UUID.fromString("b540a415-f65d-4270-9bad-7b789d124176")
  val kid                  = "Kd3WRADi5yjC5y7Ux73Lnk9cvsL5hMHplUuq5yKsBMg"
  val interopAudience      = "test.interop.pagopa.it"
  val validPublicKey       =
    "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxQ0kxRENEWE9VaWtZbTJhdVFWNwpDcmdJbjNyM2FQeE1wMFdiTjNiamZBZFNsc3AzR1o0dUJVK3F5SGVQNUF0RVZxVW9ZaUNRaForcFo3T1F5bUxQCllibHVIK3h2dWpBVUxVS3VOWi85RlhtQXU4S2VMV09TUGhDWDFkeUhSRFhJZit3QWZzZVZxU2VLTElzeUhqcTkKWXF3WUFONWYvTGdzVlA4UUpLdnhZSEtXWW5hRTVKa1lESkIwT25hZjU0U1BWRU9PNUxqczJ0bDAwLzBNeTlvSApwWjV6c2dpcjRoSlZvNEJGb3hPSzhlcTQxTzJGYlpXQWlIbTBvbFpMeG0vU3dRbXNWNGpETmNQQis4ZE1UdFFXCjg0dGtYNUZyOEpwbFRMZkxUSm1FNGJTcTJUZnAvb2czeGNxM0dpeDZGVm56RWNIMmZkbXk3STgyR3J6dURJOWIKZndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
  val validClientAssertion =
    "eyJraWQiOiJLZDNXUkFEaTV5akM1eTdVeDczTG5rOWN2c0w1aE1IcGxVdXE1eUtzQk1nIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIzZGEyYzk1NS1mY2FlLTQ1N2YtOTI2Zi02ZGM0MWI4Zjk1YTkiLCJhdWQiOiJ0ZXN0LmludGVyb3AucGFnb3BhLml0IiwibmJmIjoxNjUwNjIxODU5LCJpc3MiOiIzZGEyYzk1NS1mY2FlLTQ1N2YtOTI2Zi02ZGM0MWI4Zjk1YTkiLCJwdXJwb3NlSWQiOiJiNTQwYTQxNS1mNjVkLTQyNzAtOWJhZC03Yjc4OWQxMjQxNzYiLCJleHAiOjQxMDIzNTQ4MDAsImlhdCI6MTY1MDYyMTg1OSwianRpIjoiOGUwYWQ5YjItODc4OC00NTgxLWEwZjUtZDMyNjAxOGI5YzNhIn0.htnYZhRHcSZUvPYLS1bEgidjymZJJ4hj0FudC374oFupjdIF2xVVW9DZrFYaeiUKr9rANCrUkSmRHKeQcQ0OofJI_dha2v7C6DdTLkiMhAr6imGQEwU3vu75bdnLcOmVeq4KKAmDA6YW6ApKpd5rgNjwzfNEVBsYFW2e0v85ZaovQO36Cr8jjC04kMV8GiHA6Jonu9TfW7Vz7tVayOaI6Eg1CnCPa2lqRM30OJG03GwmtCSWlkOTPDqdpF1GI71xrg9wbczCmw5BvzBRISHpwPluqPOpxqn6Nf9Xo8DNHDaE8ZfH48Uy1T0qPsrH0Awsh8PYXgGXlp12tZbLszhaaQ"
  val modelKey: Key        = Key(
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

  val clientKey: ClientKey =
    ClientKey(key = modelKey, relationshipId = UUID.randomUUID(), name = "keyName", createdAt = OffsetDateTime.now())

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
