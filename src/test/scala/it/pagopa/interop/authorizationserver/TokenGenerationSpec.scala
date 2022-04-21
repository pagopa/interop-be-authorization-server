package it.pagopa.interop.authorizationserver

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.testkit.ScalatestRouteTest
import it.pagopa.interop.authorizationserver.api.impl.AuthApiMarshallerImpl._
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.model.ClientCredentialsResponse
import it.pagopa.interop.authorizationserver.utils.BaseSpec
import it.pagopa.interop.authorizationserver.utils.SpecData._
import it.pagopa.interop.commons.jwt.{JWTConfiguration, JWTInternalTokenConfig}
import it.pagopa.interop.commons.jwt.model.{ClientAssertionChecker, RSA, ValidClientAssertionRequest}
import it.pagopa.interop.commons.utils.PURPOSE_ID_CLAIM
import org.scalatest.matchers.should.Matchers._

import scala.concurrent.Future
import scala.util.Success

class TokenGenerationSpec extends BaseSpec with ScalatestRouteTest {

  implicit val context: Seq[(String, String)] = Seq.empty

  val jwtConfig: JWTInternalTokenConfig = JWTConfiguration.jwtInternalTokenConfig

  val clientAssertionChecker: ClientAssertionChecker = mock[ClientAssertionChecker]

  clientAssertionChecker.kid returns kid
  clientAssertionChecker.subject returns clientId.toString
  clientAssertionChecker.purposeId returns Some(purposeId.toString)

  "Consumer token generation" should {
    "succeed with correct request" in {

      val resource = eServiceAudience

      mockInteropTokenGenerator
        .generateInternalToken(
          eqTo(RSA),
          eqTo(jwtConfig.subject),
          eqTo(jwtConfig.audience.toList),
          eqTo(jwtConfig.issuer),
          eqTo(jwtConfig.durationInSeconds)
        )
        .returns(Success(internalToken))

      mockClientAssertionValidator
        .extractJwtInfo(*[ValidClientAssertionRequest])
        .returns(Success(clientAssertionChecker))

      mockAuthorizationManagementService
        .getKey(eqTo(clientId), eqTo(kid))(*[Seq[(String, String)]])
        .returns(Future.successful(clientKey))

      clientAssertionChecker.verify(*[String]).returns(Success(()))

      mockAuthorizationManagementService
        .getClient(eqTo(clientId))(*[Seq[(String, String)]])
        .returns(Future.successful(activeClient))

      mockInteropTokenGenerator
        .generate(
          clientAssertion = clientAssertion,
          audience = List(eServiceAudience),
          customClaims = Map(PURPOSE_ID_CLAIM -> purposeId.toString),
          tokenIssuer = ApplicationConfiguration.interopIdIssuer,
          validityDurationInSeconds = eServiceTokenDuration.toLong // TODO This could be an Int
        )
        .returns(Success(generatedToken))

      mockQueueService.send(expectedQueueMessage).returns(Future.successful("ok"))

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
