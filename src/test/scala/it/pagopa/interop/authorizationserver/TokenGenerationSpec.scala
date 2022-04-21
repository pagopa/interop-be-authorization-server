package it.pagopa.interop.authorizationserver

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.testkit.ScalatestRouteTest
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.authorizationserver.api.impl.AuthApiMarshallerImpl._
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.model.{ClientCredentialsResponse, JWTDetailsMessage, TokenType}
import it.pagopa.interop.authorizationserver.utils.BaseSpec
import it.pagopa.interop.commons.jwt.model.{ClientAssertionChecker, RSA, Token, ValidClientAssertionRequest}
import it.pagopa.interop.commons.utils.PURPOSE_ID_CLAIM
import org.mockito.MockitoSugar._
import org.scalatest.matchers.should.Matchers._

import java.time.OffsetDateTime
import java.util.UUID
import scala.concurrent.Future
import scala.util.Success

class TokenGenerationSpec extends BaseSpec with ScalatestRouteTest {

//  val jwtConfig: JWTInternalTokenConfig = ???
  val internalToken: Token = Token(serialized = "internal-jwt", jti = "internal-jti", iat = 0, exp = 100, nbf = 0)
  val clientId: UUID       = UUID.randomUUID()
  val purposeId: UUID      = UUID.randomUUID()

  val kid = "kid"

  val clientAssertionChecker: ClientAssertionChecker = mock[ClientAssertionChecker]

  when(clientAssertionChecker.kid).thenReturn(kid)
  when(clientAssertionChecker.subject).thenReturn(clientId.toString)
  when(clientAssertionChecker.purposeId).thenReturn(Some(purposeId.toString))

  "Consumer token generation" should {
    "succeed" in {

      implicit val context: Seq[(String, String)] = Seq.empty

      val clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
      val grantType           = "client_credentials"

      val eServiceAudience      = "e-service-audience"
      val eServiceTokenDuration = 100

      val resource = eServiceAudience

      val clientKey: ClientKey = ClientKey(
        key = Key(kty = "kty", kid = kid),
        relationshipId = UUID.randomUUID(),
        name = "keyName",
        createdAt = OffsetDateTime.now()
      )

      val client: Client = Client(
        id = clientId,
        consumerId = UUID.randomUUID(),
        name = "clientName",
        description = None,
        purposes = Seq(
          Purpose(
            purposeId = purposeId,
            states = ClientStatesChain(
              id = UUID.randomUUID(),
              eservice = ClientEServiceDetails(
                eserviceId = UUID.randomUUID(),
                state = ClientComponentState.ACTIVE,
                audience = Seq(eServiceAudience),
                voucherLifespan = eServiceTokenDuration
              ),
              agreement = ClientAgreementDetails(
                eserviceId = UUID.randomUUID(),
                consumerId = UUID.randomUUID(),
                state = ClientComponentState.ACTIVE
              ),
              purpose = ClientPurposeDetails(purposeId = purposeId, state = ClientComponentState.ACTIVE)
            )
          )
        ),
        relationships = Set.empty,
        kind = ClientKind.CONSUMER
      )

      val clientAssertion = "client-assertion"

      val generatedToken: Token = Token(serialized = "generated-jwt", jti = "qwerty", iat = 0, exp = 100, nbf = 0)

      val expected: ClientCredentialsResponse =
        ClientCredentialsResponse(
          generatedToken.serialized,
          TokenType.Bearer,
          generatedToken.exp.toInt // TODO Check this
        )

      val expectedQueueMessage = JWTDetailsMessage(
        jti = generatedToken.jti,
        iat = generatedToken.iat,
        exp = generatedToken.exp,
        clientId = clientId.toString,
        purposeId = Some(purposeId.toString),
        kid = kid
      )

      when(
        mockInteropTokenGenerator
          .generateInternalToken(eqTo(RSA), *[String], *[List[String]], *[String], *[Long])
      )
        .thenReturn(Success(internalToken))

      mockClientAssertionValidator
        .extractJwtInfo(*[ValidClientAssertionRequest])
        .returns(Success(clientAssertionChecker))

      //      verify(mockInteropTokenGenerator)
//        .generateInternalToken(
//          eqTo(RSA),
//          eqTo(jwtConfig.subject),
//          eqTo(jwtConfig.audience.toList),
//          eqTo(jwtConfig.issuer),
//          eqTo(jwtConfig.durationInSeconds)
//        )
//        .returns(Success(internalToken))

      when(
        mockAuthorizationManagementService
          .getKey(eqTo(clientId), eqTo(kid))(*[Seq[(String, String)]])
      )
        .thenReturn(Future.successful(clientKey))

      when(clientAssertionChecker.verify(*[String])).thenReturn(Success(()))

      when(
        mockAuthorizationManagementService
          .getClient(eqTo(clientId))(*[Seq[(String, String)]])
      )
        .thenReturn(Future.successful(client))

      when(
        mockInteropTokenGenerator
          .generate(
            clientAssertion = clientAssertion,
            audience = List(eServiceAudience),
            customClaims = Map(PURPOSE_ID_CLAIM -> purposeId.toString),
            tokenIssuer = ApplicationConfiguration.interopIdIssuer,
            validityDurationInSeconds = eServiceTokenDuration.toLong // TODO This could be an Int
          )
      )
        .thenReturn(Success(generatedToken))

      when(mockQueueService.send(expectedQueueMessage)).thenReturn(Future.successful("ok"))

      Get() ~> service.createToken(
        Some(clientId.toString),
        clientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.OK
        responseAs[ClientCredentialsResponse] shouldEqual expected
      }

    }
  }
}
