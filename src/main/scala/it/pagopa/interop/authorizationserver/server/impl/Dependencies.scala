package it.pagopa.interop.authorizationserver.server.impl

import akka.actor.typed.ActorSystem
import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Directives.complete
import akka.http.scaladsl.server.Route
import akka.http.scaladsl.server.directives.SecurityDirectives
import com.atlassian.oai.validator.report.ValidationReport
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import it.pagopa.interop.authorizationmanagement.client.api.{TokenGenerationApi => AuthorizationTokenGenerationApi}
import it.pagopa.interop.authorizationserver.api._
import it.pagopa.interop.authorizationserver.api.impl.{
  AuthApiMarshallerImpl,
  AuthApiServiceImpl,
  HealthApiMarshallerImpl,
  HealthServiceApiImpl,
  entityMarshallerProblem,
  problemOf
}
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.service._
import it.pagopa.interop.authorizationserver.service.impl._
import it.pagopa.interop.commons.jwt._
import it.pagopa.interop.commons.jwt.service.ClientAssertionValidator
import it.pagopa.interop.commons.jwt.service.impl.{
  DefaultClientAssertionValidator,
  DefaultInteropTokenGenerator,
  getClaimsVerifier
}
import it.pagopa.interop.commons.signer.service.SignerService
import it.pagopa.interop.commons.signer.service.impl.KMSSignerService
import it.pagopa.interop.commons.utils.AkkaUtils.PassThroughAuthenticator
import it.pagopa.interop.commons.utils.OpenapiUtils
import it.pagopa.interop.commons.utils.TypeConversions.TryOps

import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.ExecutionContextExecutor

trait Dependencies {

  def authorizationManagementService(
    blockingEc: ExecutionContextExecutor
  )(implicit ec: ExecutionContext, actorSystem: ActorSystem[_]): AuthorizationManagementServiceImpl =
    new AuthorizationManagementServiceImpl(
      AuthorizationManagementInvoker(blockingEc)(actorSystem.classicSystem),
      AuthorizationTokenGenerationApi(ApplicationConfiguration.authorizationManagementURL)
    )

  private def signerService(blockingEc: ExecutionContextExecutor): SignerService = new KMSSignerService(blockingEc)

  def getClientAssertionValidator(): Future[ClientAssertionValidator] =
    JWTConfiguration.jwtReader
      .loadKeyset()
      .map(keyset =>
        new DefaultClientAssertionValidator with PublicKeysHolder {
          var publicKeyset: Map[KID, SerializedKey]                                        = keyset
          override protected val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
            getClaimsVerifier(audience = ApplicationConfiguration.clientAssertionAudience)
        }
      )
      .toFuture

  private def interopTokenGenerator(blockingEc: ExecutionContextExecutor): DefaultInteropTokenGenerator =
    new DefaultInteropTokenGenerator(
      signerService(blockingEc),
      new PrivateKeysKidHolder {
        override val RSAPrivateKeyset: Set[KID] = ApplicationConfiguration.rsaKeysIdentifiers
        override val ECPrivateKeyset: Set[KID]  = ApplicationConfiguration.ecKeysIdentifiers
      }
    )(blockingEc)

  private def queueService(blockingEc: ExecutionContextExecutor): QueueServiceImpl =
    QueueServiceImpl(ApplicationConfiguration.jwtQueueUrl)(blockingEc)

  private def authApiService(
    clientAssertionValidator: ClientAssertionValidator,
    blockingEc: ExecutionContextExecutor
  )(implicit actorSystem: ActorSystem[_], ec: ExecutionContext): AuthApiService =
    AuthApiServiceImpl(
      authorizationManagementService(blockingEc),
      clientAssertionValidator,
      interopTokenGenerator(blockingEc),
      queueService(blockingEc)
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
      problemOf(StatusCodes.BadRequest, OpenapiUtils.errorFromRequestValidationReport(report))
    complete(error.status, error)(entityMarshallerProblem)
  }

}
