package it.pagopa.interop.authorizationserver.server.impl

import akka.actor.typed.ActorSystem
import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Directives.complete
import akka.http.scaladsl.server.Route
import akka.http.scaladsl.server.directives.SecurityDirectives
import com.atlassian.oai.validator.report.ValidationReport
import it.pagopa.interop.authorizationmanagement.client.api.{TokenGenerationApi => AuthorizationTokenGenerationApi}
import it.pagopa.interop.authorizationserver.api._
import it.pagopa.interop.authorizationserver.api.impl.{
  AuthApiMarshallerImpl,
  AuthApiServiceImpl,
  HealthApiMarshallerImpl,
  HealthServiceApiImpl
}
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.error.ResponseHandlers.serviceCode
import it.pagopa.interop.authorizationserver.service._
import it.pagopa.interop.authorizationserver.service.impl._
import it.pagopa.interop.clientassertionvalidation.ClientAssertionValidator
import it.pagopa.interop.commons.files.service.FileManager
import it.pagopa.interop.commons.jwt._
import it.pagopa.interop.commons.jwt.service.impl.DefaultInteropTokenGenerator
import it.pagopa.interop.commons.queue.config.SQSHandlerConfig
import it.pagopa.interop.commons.queue.impl.SQSHandler
import it.pagopa.interop.commons.ratelimiter.RateLimiter
import it.pagopa.interop.commons.ratelimiter.impl.RedisRateLimiter
import it.pagopa.interop.commons.signer.service.SignerService
import it.pagopa.interop.commons.signer.service.impl.KMSSignerService
import it.pagopa.interop.commons.utils.AkkaUtils.PassThroughAuthenticator
import it.pagopa.interop.commons.utils.OpenapiUtils
import it.pagopa.interop.commons.utils.errors.{Problem => CommonProblem}
import it.pagopa.interop.commons.utils.service.OffsetDateTimeSupplier

import scala.concurrent.{ExecutionContext, ExecutionContextExecutor}

trait Dependencies {

  val dateTimeSupplier: OffsetDateTimeSupplier = OffsetDateTimeSupplier

  def authorizationManagementService(
    blockingEc: ExecutionContextExecutor
  )(implicit actorSystem: ActorSystem[_]): AuthorizationManagementServiceImpl =
    new AuthorizationManagementServiceImpl(
      AuthorizationManagementInvoker(blockingEc)(actorSystem.classicSystem),
      AuthorizationTokenGenerationApi(ApplicationConfiguration.authorizationManagementURL)
    )(blockingEc)

  private def signerService(blockingEc: ExecutionContextExecutor): SignerService = new KMSSignerService(blockingEc)

  private def interopTokenGenerator(blockingEc: ExecutionContextExecutor): DefaultInteropTokenGenerator =
    new DefaultInteropTokenGenerator(
      signerService(blockingEc),
      new PrivateKeysKidHolder {
        override val RSAPrivateKeyset: Set[KID] = ApplicationConfiguration.rsaKeysIdentifiers
        override val ECPrivateKeyset: Set[KID]  = ApplicationConfiguration.ecKeysIdentifiers
      }
    )(blockingEc)

  private def queueService(blockingEc: ExecutionContextExecutor): QueueServiceImpl = {
    val sqsHandlerConfig: SQSHandlerConfig = SQSHandlerConfig(queueUrl = ApplicationConfiguration.jwtQueueUrl)
    val sqsHandler: SQSHandler             = SQSHandler(sqsHandlerConfig)(blockingEc)
    QueueServiceImpl(sqsHandler)
  }

  private def rateLimiter: RateLimiter =
    RedisRateLimiter(ApplicationConfiguration.rateLimiterConfigs, dateTimeSupplier)

  private def authApiService(
    clientAssertionValidator: ClientAssertionValidator,
    blockingEc: ExecutionContextExecutor
  )(implicit actorSystem: ActorSystem[_], ec: ExecutionContext): AuthApiService =
    AuthApiServiceImpl(
      authorizationManagementService(blockingEc),
      clientAssertionValidator,
      interopTokenGenerator(blockingEc),
      queueService(blockingEc),
      FileManager.get(FileManager.S3)(blockingEc),
      rateLimiter,
      dateTimeSupplier
    )

  def authApi(clientAssertionValidator: ClientAssertionValidator, blockingEc: ExecutionContextExecutor)(implicit
    ec: ExecutionContext,
    actorSystem: ActorSystem[_]
  ): AuthApi = new AuthApi(
    authApiService(clientAssertionValidator, blockingEc),
    AuthApiMarshallerImpl,
    SecurityDirectives.authenticateOAuth2("SecurityRealm", PassThroughAuthenticator)
  )

  val healthApi: HealthApi = new HealthApi(
    new HealthServiceApiImpl(),
    HealthApiMarshallerImpl,
    SecurityDirectives.authenticateOAuth2("SecurityRealm", PassThroughAuthenticator),
    loggingEnabled = false
  )

  val validationExceptionToRoute: ValidationReport => Route = report => {
    val error =
      CommonProblem(StatusCodes.BadRequest, OpenapiUtils.errorFromRequestValidationReport(report), serviceCode, None)
    complete(error.status, error)
  }

}
