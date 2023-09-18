package it.pagopa.interop.clientassertionvalidation

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import it.pagopa.interop.authorizationmanagement.client.model._

import java.time.{OffsetDateTime, ZoneOffset}
import java.util.{Date, UUID}

object SpecData {
  final val timestamp = OffsetDateTime.of(2022, 12, 31, 11, 22, 33, 44, ZoneOffset.UTC)

  val consumerId: UUID       = UUID.randomUUID()
  val eServiceId: UUID       = UUID.randomUUID()
  val descriptorId: UUID     = UUID.randomUUID()
  val agreementId: UUID      = UUID.randomUUID()
  val purposeVersionId: UUID = UUID.randomUUID()

  val clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  val grantType           = "client_credentials"

  val assertionExpirationTime: Date =
    Date.from(OffsetDateTime.of(2099, 12, 31, 23, 59, 59, 59, ZoneOffset.UTC).toInstant)
  val rsaKey: RSAKey                = new RSAKeyGenerator(2048).generate
  val rsaKid: String                = rsaKey.computeThumbprint().toString
  val rsaPrivateKey: String         = rsaKey.toJSONString

  val clientId: UUID           = UUID.randomUUID()
  val purposeId: UUID          = UUID.randomUUID()
  val clientAssertionAlgorithm = "RS256"
  val clientAssertionAudience  = "test.interop.pagopa.it"
  val modelKey: JWKKey         = JWKKey(
    kty = "RSA",
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

  val eServiceAudience      = "e-service-audience"
  val eServiceTokenDuration = 100

  val anotherModelKey: JWKKey = modelKey.copy(n =
    Some(
      "oWHaq1cUlIUM1kvzJABltbilH_UtVHXVDSyUOLiVNffGpguOGj6ngW6ExYZX-3vnXYZ27LRFBxydA912yG3WsPy412MNdUT0h6yMVkju3212OMsMWIO5b1Sp9jxpQqKtpjvzYM5Bh-mFWjug3WVnwY8rjiWx3XnNudLgjSZxteprvQ4GCAmYCiiq6t2D-_0nwvmi162ySGtLXEzRUEL-AkwzS0UV0uNzvFxqkuAPvEAOmb28yqKgmHQnQwf3t9NsS3pqV1OaHmfQeeWQeVhPOfzAFsZhOH0GqZwPTCP2_Z9zp9HIdfVgUa4yvFfKo48QfePTT8Dy8xM9bhuAu0gdgw"
    )
  )

  def makeClient(
    purposeState: ClientComponentState = ClientComponentState.ACTIVE,
    eServiceState: ClientComponentState = ClientComponentState.ACTIVE,
    agreementState: ClientComponentState = ClientComponentState.ACTIVE,
    kind: ClientKind = ClientKind.CONSUMER,
    purposeId: UUID = purposeId
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

}
