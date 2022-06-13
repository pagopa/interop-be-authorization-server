//package it.pagopa.interop.authorizationserver
//
//import akka.http.scaladsl.model.StatusCodes
//import akka.http.scaladsl.testkit.ScalatestRouteTest
//import it.pagopa.interop.authorizationmanagement.client.invoker.{ApiError => AuthorizationManagementApiError}
//import it.pagopa.interop.authorizationmanagement.client.model.{ClientComponentState, ClientKind}
//import it.pagopa.interop.authorizationserver.api.impl.AuthApiMarshallerImpl._
//import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
//import it.pagopa.interop.authorizationserver.model.{ClientCredentialsResponse, JWTDetailsMessage, TokenType}
//import it.pagopa.interop.authorizationserver.utils.{BaseSpec, SpecHelper}
//import it.pagopa.interop.authorizationserver.utils.SpecData._
//import it.pagopa.interop.commons.jwt.{JWTConfiguration, JWTInternalTokenConfig}
//import org.scalatest.matchers.should.Matchers._
//import spray.json.JsonWriter
//
//import java.util.UUID
//import scala.concurrent.Future
//
//class TokenGenerationSpec extends BaseSpec with SpecHelper with ScalatestRouteTest {
//
//  implicit val context: Seq[(String, String)] = Seq.empty
//
//  val jwtConfig: JWTInternalTokenConfig = JWTConfiguration.jwtInternalTokenConfig
//
//  "Token generation" should {
//    "fail on wrong client assertion type" in {
//      val wrongClientAssertionType = "something-wrong"
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        wrongClientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "fail on wrong grant type" in {
//      val wrongGrantType = "something-wrong"
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        wrongGrantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "fail on malformed assertion" in {
//      val malformedAssertion = "something-wrong"
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        malformedAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "fail on wrong audience in assertion" in {
//
//      Get() ~> customService(clientAssertionAudience = "another-audience").createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "fail if client ID in the assertion is different from the parameter client ID" in {
//      Get() ~> service.createToken(
//        Some(UUID.randomUUID().toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "fail if kid in the assertion is not found for the given client ID" in {
//      mockInternalTokenGeneration(jwtConfig)
//
//      (mockAuthorizationManagementService
//        .getKeyWithClient(_: UUID, _: String)(_: Seq[(String, String)]))
//        .expects(clientId, clientAssertionKid, *)
//        .once()
//        .returns(
//          Future.failed(AuthorizationManagementApiError(code = 404, message = "something", responseContent = None))
//        )
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "fail if the assertion is not signed with the public key corresponding to the kid" in {
//      mockInternalTokenGeneration(jwtConfig)
//      mockKeyRetrieve(keyWithClient.copy(key = anotherModelKey))
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "succeed even if publish on queue fails" in {
//      mockInternalTokenGeneration(jwtConfig)
//      mockKeyRetrieve()
//      mockConsumerTokenGeneration()
//
//      (mockQueueService
//        .send(_: JWTDetailsMessage)(_: JsonWriter[JWTDetailsMessage]))
//        .expects(expectedQueueMessage, *)
//        .once()
//        .returns(Future.failed(new Throwable()))
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.OK
//      }
//    }
//
//  }
//
//  "Consumer token generation" should {
//    "succeed with correct request" in {
//      mockInternalTokenGeneration(jwtConfig)
//      mockKeyRetrieve()
//      mockConsumerTokenGeneration()
//      mockQueueMessagePublication()
//
//      val expectedResponse =
//        ClientCredentialsResponse(generatedToken.serialized, TokenType.Bearer, eServiceTokenDuration)
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.OK
//        responseAs[ClientCredentialsResponse] shouldEqual expectedResponse
//      }
//    }
//
//    "fail if purpose id is not assigned to the client" in {
//      mockInternalTokenGeneration(jwtConfig)
//      mockKeyRetrieve(result = keyWithClient.copy(client = activeClient.copy(purposes = Seq.empty)))
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "fail if Purpose is not active" in {
//      mockInternalTokenGeneration(jwtConfig)
//      mockKeyRetrieve(result = keyWithClient.copy(client = makeClient(purposeState = ClientComponentState.INACTIVE)))
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "fail if EService is not active" in {
//      mockInternalTokenGeneration(jwtConfig)
//      mockKeyRetrieve(result = keyWithClient.copy(client = makeClient(eServiceState = ClientComponentState.INACTIVE)))
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//    "fail if Agreement is not active" in {
//      mockInternalTokenGeneration(jwtConfig)
//      mockKeyRetrieve(result = keyWithClient.copy(client = makeClient(agreementState = ClientComponentState.INACTIVE)))
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }
//
//  }
//
//  "API token generation" should {
//    "succeed with correct request" in {
//      val apiClient = makeClient(kind = ClientKind.API).copy(purposes = Seq.empty)
//
//      mockInternalTokenGeneration(jwtConfig)
//      mockKeyRetrieve(result = keyWithClient.copy(client = apiClient))
//      mockApiTokenGeneration()
//
//      val expectedResponse =
//        ClientCredentialsResponse(
//          generatedToken.serialized,
//          TokenType.Bearer,
//          ApplicationConfiguration.generatedM2mJwtDuration
//        )
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.OK
//        responseAs[ClientCredentialsResponse] shouldEqual expectedResponse
//      }
//    }
//  }
//}
