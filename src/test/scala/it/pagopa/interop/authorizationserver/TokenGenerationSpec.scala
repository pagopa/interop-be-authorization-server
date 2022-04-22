package it.pagopa.interop.authorizationserver

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.testkit.ScalatestRouteTest
import it.pagopa.interop.authorizationmanagement.client.invoker.{ApiError => AuthorizationManagementApiError}
import it.pagopa.interop.authorizationmanagement.client.model.{ClientComponentState, ClientKind}
import it.pagopa.interop.authorizationserver.api.impl.AuthApiMarshallerImpl._
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.model.{ClientCredentialsResponse, JWTDetailsMessage, TokenType}
import it.pagopa.interop.authorizationserver.utils.{BaseSpec, SpecHelper}
import it.pagopa.interop.authorizationserver.utils.SpecData._
import it.pagopa.interop.commons.jwt.{JWTConfiguration, JWTInternalTokenConfig}
import org.scalatest.matchers.should.Matchers._
import spray.json.JsonWriter

import java.util.UUID
import scala.concurrent.Future

class TokenGenerationSpec extends BaseSpec with SpecHelper with ScalatestRouteTest {

  implicit val context: Seq[(String, String)] = Seq.empty

  val jwtConfig: JWTInternalTokenConfig = JWTConfiguration.jwtInternalTokenConfig

  "Token generation" should {
    "fail on wrong client assertion type" in {
      val resource                 = eServiceAudience
      val wrongClientAssertionType = "something-wrong"

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        wrongClientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail on wrong grant type" in {
      val resource       = eServiceAudience
      val wrongGrantType = "something-wrong"

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        wrongGrantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail on malformed assertion" in {
      val resource           = eServiceAudience
      val malformedAssertion = "something-wrong"

      Get() ~> service.createToken(
        Some(clientId.toString),
        malformedAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail on wrong audience in assertion" in {
      val resource = eServiceAudience

      Get() ~> customService(interopAudience = "another-audience").createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail if client ID in the assertion is different from the parameter client ID" in {
      val resource = eServiceAudience

      Get() ~> service.createToken(
        Some(UUID.randomUUID().toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail if kid in the assertion is not found for the given client ID" in {
      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)

      (mockAuthorizationManagementService
        .getKey(_: UUID, _: String)(_: Seq[(String, String)]))
        .expects(clientId, kid, *)
        .once()
        .returns(
          Future.failed(AuthorizationManagementApiError(code = 404, message = "something", responseContent = None))
        )

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail if the assertion is not signed with the public key corresponding to the kid" in {
      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)
      mockKeyRetrieve(clientKey.copy(key = anotherModelKey))

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "succeed even if publish on queue fails" in {
      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)
      mockKeyRetrieve()
      mockClientRetrieve()
      mockConsumerTokenGeneration()

      (mockQueueService
        .send(_: JWTDetailsMessage)(_: JsonWriter[JWTDetailsMessage]))
        .expects(expectedQueueMessage, *)
        .once()
        .returns(Future.failed(new Throwable()))

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.OK
      }
    }

  }

  "Consumer token generation" should {
    "succeed with correct request" in {
      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)
      mockKeyRetrieve()
      mockClientRetrieve()
      mockConsumerTokenGeneration()
      mockQueueMessagePublication()

      val expectedResponse =
        ClientCredentialsResponse(generatedToken.serialized, TokenType.Bearer, eServiceTokenDuration)

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.OK
        responseAs[ClientCredentialsResponse] shouldEqual expectedResponse
      }
    }

    "fail if purpose id is not assigned to the client" in {
      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)
      mockKeyRetrieve()
      mockClientRetrieve(activeClient.copy(purposes = Seq.empty))

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail if Purpose is not active" in {
      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)
      mockKeyRetrieve()
      mockClientRetrieve(makeClient(purposeState = ClientComponentState.INACTIVE))

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail if EService is not active" in {
      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)
      mockKeyRetrieve()
      mockClientRetrieve(makeClient(eServiceState = ClientComponentState.INACTIVE))

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail if Agreement is not active" in {
      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)
      mockKeyRetrieve()
      mockClientRetrieve(makeClient(agreementState = ClientComponentState.INACTIVE))

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

//    TODO Implement this if resource implementation will not be reverted
//    "fail if resource does not correspond to EService audience" in {}
  }

  "API token generation" should {
    "succeed with correct request" in {
      val resource = interopAudience

      val apiClient = makeClient(kind = ClientKind.API).copy(purposes = Seq.empty)

      mockInternalTokenGeneration(jwtConfig)
      mockKeyRetrieve()
      mockClientRetrieve(apiClient)
      mockApiTokenGeneration()
      mockQueueMessagePublication()

      val expectedResponse =
        ClientCredentialsResponse(
          generatedToken.serialized,
          TokenType.Bearer,
          ApplicationConfiguration.interopTokenDuration
        )

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.OK
        responseAs[ClientCredentialsResponse] shouldEqual expectedResponse
      }
    }

//    TODO Implement this if resource implementation will not be reverted
//    "fail if resource does not correspond to Interop audience" in {}
  }
}
