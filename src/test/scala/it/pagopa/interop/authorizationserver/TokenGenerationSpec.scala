package it.pagopa.interop.authorizationserver

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.testkit.ScalatestRouteTest
import it.pagopa.interop.authorizationserver.api.impl.AuthApiMarshallerImpl._
import it.pagopa.interop.authorizationserver.model.ClientCredentialsResponse
import it.pagopa.interop.authorizationmanagement.client.invoker.{ApiError => AuthorizationManagementApiError}
import it.pagopa.interop.authorizationserver.utils.SpecData._
import it.pagopa.interop.authorizationserver.utils.{BaseSpec, SpecHelper}
import it.pagopa.interop.commons.jwt.{JWTConfiguration, JWTInternalTokenConfig}
import org.scalatest.matchers.should.Matchers._

import java.util.UUID
import scala.concurrent.Future

class TokenGenerationSpec extends BaseSpec with SpecHelper with ScalatestRouteTest {

  implicit val context: Seq[(String, String)] = Seq.empty

  val jwtConfig: JWTInternalTokenConfig = JWTConfiguration.jwtInternalTokenConfig

  "Consumer token generation" should {
    "succeed with correct request" in {
      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)
      mockKeyRetrieve()
      mockClientRetrieve()
      mockTokenGeneration()
      mockQueueMessagePublication()

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

    "fail on wrong client assertion type" in {
      val resource                 = eServiceAudience
      val wrongClientAssertionType = "something-wrong"

      mockInternalTokenGeneration(jwtConfig)

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

      mockInternalTokenGeneration(jwtConfig)

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

      mockInternalTokenGeneration(jwtConfig)

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

      mockInternalTokenGeneration(jwtConfig)

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

      mockInternalTokenGeneration(jwtConfig)

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

      mockAuthorizationManagementService
        .getKey(eqTo(clientId), eqTo(kid))(*[Seq[(String, String)]])
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

  }
}
