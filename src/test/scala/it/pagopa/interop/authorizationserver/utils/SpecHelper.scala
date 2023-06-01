package it.pagopa.interop.authorizationserver.utils

import com.typesafe.scalalogging.LoggerTakingImplicit
import it.pagopa.interop.authorizationmanagement.client.model.KeyWithClient
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.model.JWTDetailsMessage
import it.pagopa.interop.authorizationserver.utils.SpecData._
import it.pagopa.interop.clientassertionvalidation.SpecData.{
  consumerId,
  eServiceAudience,
  eServiceTokenDuration,
  rsaKid
}
import it.pagopa.interop.commons.logging.ContextFieldsToLog
import it.pagopa.interop.commons.ratelimiter.model.RateLimitStatus
import it.pagopa.interop.commons.utils.{ORGANIZATION_ID_CLAIM, PURPOSE_ID_CLAIM}
import org.scalatest.time.SpanSugar.convertIntToGrainOfTime
import spray.json.JsonWriter

import java.util.UUID
import scala.concurrent.{ExecutionContext, Future}

trait SpecHelper { self: BaseSpec =>

  def mockKeyRetrieve(result: KeyWithClient = localKeyWithClient) =
    (mockAuthorizationManagementService
      .getKeyWithClient(_: UUID, _: String)(_: Seq[(String, String)]))
      .expects(clientId, rsaKid, *)
      .once()
      .returns(Future.successful(result))

  def mockConsumerTokenGeneration() =
    (mockInteropTokenGenerator
      .generate(_: String, _: List[String], _: Map[String, String], _: String, _: Long, _: Boolean))
      .expects(
        validClientAssertion,
        List(eServiceAudience),
        Map(PURPOSE_ID_CLAIM -> purposeId.toString),
        ApplicationConfiguration.generatedJwtIssuer,
        eServiceTokenDuration.toLong,
        false
      )
      .once()
      .returns(Future.successful(generatedToken.copy(expIn = eServiceTokenDuration.toLong)))

  def mockApiTokenGeneration() =
    (mockInteropTokenGenerator
      .generate(_: String, _: List[String], _: Map[String, String], _: String, _: Long, _: Boolean))
      .expects(
        validClientAssertion,
        ApplicationConfiguration.generatedM2mJwtAudience.toList,
        Map(ORGANIZATION_ID_CLAIM -> consumerId.toString),
        ApplicationConfiguration.generatedJwtIssuer,
        ApplicationConfiguration.generatedM2mJwtDuration.toLong,
        true
      )
      .once()
      .returns(Future.successful(generatedToken.copy(expIn = ApplicationConfiguration.generatedM2mJwtDuration.toLong)))

  def mockQueueMessagePublication() =
    (mockQueueService
      .send(_: JWTDetailsMessage)(_: JsonWriter[JWTDetailsMessage]))
      .expects(expectedQueueMessage, *)
      .once()
      .returns(Future.successful("ok"))

  def mockRateLimiterExec() =
    (mockRateLimiter
      .rateLimiting(_: UUID)(
        _: ExecutionContext,
        _: LoggerTakingImplicit[ContextFieldsToLog],
        _: Seq[(String, String)]
      ))
      .expects(*, *, *, *)
      .once()
      .returns(Future.successful(RateLimitStatus(10, 10, 1.second)))

}
