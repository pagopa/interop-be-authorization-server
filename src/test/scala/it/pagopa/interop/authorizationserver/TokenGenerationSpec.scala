package it.pagopa.interop.authorizationserver

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.testkit.ScalatestRouteTest
import it.pagopa.interop.authorizationmanagement.client.model.{ClientComponentState, ClientKind}
import it.pagopa.interop.authorizationserver.api.impl.AuthApiMarshallerImpl._
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.error.AuthServerErrors.KeyNotFound
import it.pagopa.interop.authorizationserver.model.{ClientCredentialsResponse, JWTDetailsMessage, TokenType}
import it.pagopa.interop.authorizationserver.utils.SpecData._
import it.pagopa.interop.authorizationserver.utils.{BaseSpec, SpecData, SpecHelper}
import it.pagopa.interop.clientassertionvalidation.SpecData.{
  anotherModelKey,
  clientAssertionType,
  eServiceTokenDuration,
  grantType,
  makeClient,
  rsaKid
}
import it.pagopa.interop.commons.utils.CORRELATION_ID_HEADER
import org.scalatest.matchers.should.Matchers._
import spray.json.JsonWriter

import java.util.UUID
import scala.concurrent.Future

class TokenGenerationSpec extends BaseSpec with SpecHelper with ScalatestRouteTest {

  implicit val context: Seq[(String, String)] = Seq(CORRELATION_ID_HEADER -> correlationId)

  "Token generation" should {

    "not invoke authorization management if client assertion validation fails" in {
      val wrongClientAssertionType = "something-wrong"

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        wrongClientAssertionType,
        grantType
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "fail if kid in the assertion is not found for the given client ID" in {
      (mockAuthorizationManagementService
        .getKeyWithClient(_: UUID, _: String)(_: Seq[(String, String)]))
        .expects(clientId, rsaKid, *)
        .once()
        .returns(Future.failed(KeyNotFound(clientId, rsaKid)))

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "skip rate limiting if client assertion signature verification fails" in {
      mockKeyRetrieve(localKeyWithClient.copy(key = anotherModelKey))

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "trigger rate limiting if platform state verification fails" in {
      mockKeyRetrieve(result =
        localKeyWithClient.copy(client = makeClient(purposeState = ClientComponentState.INACTIVE))
      )
      mockRateLimiterExec()

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType
      ) ~> check {
        status shouldEqual StatusCodes.BadRequest
      }
    }

    "succeed even if publish on queue fails" in {
      mockKeyRetrieve()
      mockConsumerTokenGeneration()
      mockRateLimiterExec()

      (mockQueueService
        .send(_: JWTDetailsMessage)(_: JsonWriter[JWTDetailsMessage]))
        .expects(expectedQueueMessage, *)
        .once()
        .returns(Future.failed(new Throwable()))

      (() => mockDateTimeSupplier.get()).expects().returning(SpecData.timestamp).once()

      mockFileManagerStore("whateverPath")

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType
      ) ~> check {
        status shouldEqual StatusCodes.OK
      }
    }

  }

  "Consumer token generation" should {
    "succeed with correct request" in {
      mockKeyRetrieve()
      mockConsumerTokenGeneration()
      mockRateLimiterExec()
      mockQueueMessagePublication()

      val expectedResponse =
        ClientCredentialsResponse(generatedToken.serialized, TokenType.Bearer, eServiceTokenDuration)

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType
      ) ~> check {
        status shouldEqual StatusCodes.OK
        responseAs[ClientCredentialsResponse] shouldEqual expectedResponse
      }
    }

  }

  "API token generation" should {
    "succeed with correct request" in {
      val apiClient = makeClient(kind = ClientKind.API).copy(purposes = Seq.empty)

      mockKeyRetrieve(result = localKeyWithClient.copy(client = apiClient))
      mockApiTokenGeneration()
      mockRateLimiterExec()

      val expectedResponse =
        ClientCredentialsResponse(
          generatedToken.serialized,
          TokenType.Bearer,
          ApplicationConfiguration.generatedM2mJwtDuration
        )

      Get() ~> service.createToken(
        Some(clientId.toString),
        validClientAssertion,
        clientAssertionType,
        grantType
      ) ~> check {
        status shouldEqual StatusCodes.OK
        responseAs[ClientCredentialsResponse] shouldEqual expectedResponse
      }
    }
  }
}
