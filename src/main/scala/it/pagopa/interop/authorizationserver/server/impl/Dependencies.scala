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
import it.pagopa.interop.commons.signer.service.impl.KMSSignerServiceImpl
import it.pagopa.interop.commons.utils.AkkaUtils.PassThroughAuthenticator
import it.pagopa.interop.commons.utils.OpenapiUtils
import it.pagopa.interop.commons.utils.TypeConversions.TryOps
import it.pagopa.interop.commons.utils.errors.GenericComponentErrors.ValidationRequestError

import scala.concurrent.{ExecutionContext, Future}

trait Dependencies {

  def authorizationManagementService()(implicit
    blockingEc: ExecutionContext,
    actorSystem: ActorSystem[_]
  ): AuthorizationManagementServiceImpl =
    new AuthorizationManagementServiceImpl(
      AuthorizationManagementInvoker()(actorSystem.classicSystem, blockingEc),
      AuthorizationTokenGenerationApi(ApplicationConfiguration.authorizationManagementURL)
    )(blockingEc)

  private def signerService()(implicit actorSystem: ActorSystem[_], blockingEc: ExecutionContext): SignerService =
    KMSSignerServiceImpl(ApplicationConfiguration.signerMaxConnections)(actorSystem.classicSystem, blockingEc)

  def getClientAssertionValidator()(implicit ec: ExecutionContext): Future[ClientAssertionValidator] =
    JWTConfiguration.jwtReader
      .loadKeyset()
      .toFuture
      .map(keyset =>
        new DefaultClientAssertionValidator with PublicKeysHolder {
          var publicKeyset: Map[KID, SerializedKey]                                        = keyset
          override protected val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
            getClaimsVerifier(audience = ApplicationConfiguration.clientAssertionAudience)
        }
      )

  private def interopTokenGenerator()(implicit
    blockingEc: ExecutionContext,
    actorSystem: ActorSystem[_]
  ): DefaultInteropTokenGenerator = new DefaultInteropTokenGenerator(
    signerService()(actorSystem, blockingEc),
    new PrivateKeysKidHolder {
      override val RSAPrivateKeyset: Set[KID] = ApplicationConfiguration.rsaKeysIdentifiers
      override val ECPrivateKeyset: Set[KID]  = ApplicationConfiguration.ecKeysIdentifiers
    }
  )(blockingEc)

  private def queueService()(implicit blockingEc: ExecutionContext): QueueServiceImpl =
    QueueServiceImpl(ApplicationConfiguration.jwtQueueUrl)(blockingEc)

  private def authApiService(
    clientAssertionValidator: ClientAssertionValidator
  )(implicit blockingEc: ExecutionContext, actorSystem: ActorSystem[_]): AuthApiService =
    AuthApiServiceImpl(
      authorizationManagementService()(blockingEc, actorSystem),
      clientAssertionValidator,
      interopTokenGenerator()(blockingEc, actorSystem),
      queueService()(blockingEc)
    )(blockingEc)

  def authApi(
    clientAssertionValidator: ClientAssertionValidator
  )(implicit blockingEc: ExecutionContext, actorSystem: ActorSystem[_]): AuthApi = new AuthApi(
    authApiService(clientAssertionValidator)(blockingEc, actorSystem),
    AuthApiMarshallerImpl,
    SecurityDirectives.authenticateOAuth2("SecurityRealm", PassThroughAuthenticator)
  )

  val healthApi: HealthApi = new HealthApi(
    new HealthServiceApiImpl(),
    HealthApiMarshallerImpl,
    SecurityDirectives.authenticateOAuth2("SecurityRealm", PassThroughAuthenticator)
  )

  val validationExceptionToRoute: ValidationReport => Route = report => {
    val error =
      problemOf(StatusCodes.BadRequest, ValidationRequestError(OpenapiUtils.errorFromRequestValidationReport(report)))
    complete(error.status, error)(AuthApiMarshallerImpl.toEntityMarshallerProblem)
  }

}
