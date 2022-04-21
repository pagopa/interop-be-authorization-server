package it.pagopa.interop.authorizationserver

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.testkit.ScalatestRouteTest
import it.pagopa.interop.authorizationserver.api.impl.AuthApiMarshallerImpl._
import it.pagopa.interop.authorizationserver.model.ClientCredentialsResponse
import it.pagopa.interop.authorizationserver.utils.SpecData._
import it.pagopa.interop.authorizationserver.utils.{BaseSpec, SpecHelper}
import it.pagopa.interop.commons.jwt.model.{ClientAssertionChecker, ValidClientAssertionRequest}
import it.pagopa.interop.commons.jwt.{JWTConfiguration, JWTInternalTokenConfig}
import org.scalatest.matchers.should.Matchers._

import scala.util.Success

class TokenGenerationSpec extends BaseSpec with SpecHelper with ScalatestRouteTest {

  implicit val context: Seq[(String, String)] = Seq.empty

  val jwtConfig: JWTInternalTokenConfig = JWTConfiguration.jwtInternalTokenConfig

  val clientAssertionChecker: ClientAssertionChecker = mock[ClientAssertionChecker]

  clientAssertionChecker.kid returns kid
  clientAssertionChecker.subject returns clientId.toString
  clientAssertionChecker.purposeId returns Some(purposeId.toString)

  "Consumer token generation" should {
    "succeed with correct request" in {

      val resource = eServiceAudience

      mockInternalTokenGeneration(jwtConfig)
      mockClientAssertionValidator
        .extractJwtInfo(*[ValidClientAssertionRequest])
        .returns(Success(clientAssertionChecker))

      mockKeyRetrieve()
      clientAssertionChecker.verify(*[String]).returns(Success(()))
      mockClientRetrieve()
      mockTokenGeneration()
      mockQueueMessagePublication()

      Get() ~> service.createToken(
        Some(clientId.toString),
        clientAssertion,
        clientAssertionType,
        grantType,
        resource
      ) ~> check {
        status shouldEqual StatusCodes.OK
        responseAs[ClientCredentialsResponse] shouldEqual expectedResponse
      }

    }
  }
}
