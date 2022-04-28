package it.pagopa.interop.authorizationserver.server.impl

import akka.actor.CoordinatedShutdown
import akka.http.scaladsl.Http
import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Directives.complete
import akka.http.scaladsl.server.directives.SecurityDirectives
import akka.management.scaladsl.AkkaManagement
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import it.pagopa.interop.authorizationserver.api._
import it.pagopa.interop.authorizationserver.api.impl.{
  AuthApiMarshallerImpl,
  AuthApiServiceImpl,
  HealthApiMarshallerImpl,
  HealthServiceApiImpl,
  problemOf
}
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.common.system.{classicActorSystem, executionContext}
import it.pagopa.interop.authorizationserver.server.Controller
import it.pagopa.interop.authorizationserver.service._
import it.pagopa.interop.authorizationserver.service.impl._
import it.pagopa.interop.authorizationmanagement.client.api.{
  ClientApi => AuthorizationClientApi,
  KeyApi => AuthorizationKeyApi
}
import it.pagopa.interop.commons.jwt._
import it.pagopa.interop.commons.jwt.service.impl.{
  DefaultClientAssertionValidator,
  DefaultInteropTokenGenerator,
  getClaimsVerifier
}
import it.pagopa.interop.commons.jwt.service.{ClientAssertionValidator, InteropTokenGenerator}
import it.pagopa.interop.commons.utils.AkkaUtils.PassThroughAuthenticator
import it.pagopa.interop.commons.utils.TypeConversions.TryOps
import it.pagopa.interop.commons.utils.errors.GenericComponentErrors.ValidationRequestError
import it.pagopa.interop.commons.utils.{CORSSupport, OpenapiUtils}
import it.pagopa.interop.commons.vault.service.VaultService
import it.pagopa.interop.commons.vault.service.impl.{DefaultVaultClient, DefaultVaultService}
import kamon.Kamon

import scala.concurrent.Future
import scala.util.{Failure, Success}
//shuts down the actor system in case of startup errors
case object StartupErrorShutdown extends CoordinatedShutdown.Reason

trait AuthorizationManagementDependency {
  val authorizationManagementClientApi: AuthorizationClientApi = AuthorizationClientApi(
    ApplicationConfiguration.authorizationManagementURL
  )
  val authorizationManagementKeyApi: AuthorizationKeyApi       = AuthorizationKeyApi(
    ApplicationConfiguration.authorizationManagementURL
  )
  val authorizationManagementService                           =
    new AuthorizationManagementServiceImpl(
      AuthorizationManagementInvoker(),
      authorizationManagementKeyApi,
      authorizationManagementClientApi
    )
}

trait VaultServiceDependency {
  val vaultService: VaultService = new DefaultVaultService with DefaultVaultClient.DefaultClientInstance
}

object Main extends App with CORSSupport with VaultServiceDependency with AuthorizationManagementDependency {

  val dependenciesLoaded: Future[(ClientAssertionValidator, InteropTokenGenerator)] = for {
    keyset <- JWTConfiguration.jwtReader.loadKeyset().toFuture
    clientAssertionValidator = new DefaultClientAssertionValidator with PublicKeysHolder {
      var publicKeyset: Map[KID, SerializedKey]                                        = keyset
      override protected val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
        getClaimsVerifier(audience = ApplicationConfiguration.clientAssertionAudience)
    }
    interopTokenGenerator    = new DefaultInteropTokenGenerator with PrivateKeysHolder {
      override val RSAPrivateKeyset: Map[KID, SerializedKey] =
        vaultService.readBase64EncodedData(ApplicationConfiguration.rsaPrivatePath)
      override val ECPrivateKeyset: Map[KID, SerializedKey]  =
        Map.empty
    }
  } yield (clientAssertionValidator, interopTokenGenerator)

  dependenciesLoaded.transformWith {
    case Success((clientAssertionValidator, interopTokenGenerator)) =>
      launchApp(clientAssertionValidator, interopTokenGenerator)
    case Failure(ex)                                                =>
      classicActorSystem.log.error(s"Startup error: ${ex.getMessage}")
      classicActorSystem.log.error(s"${ex.getStackTrace.mkString("\n")}")
      CoordinatedShutdown(classicActorSystem).run(StartupErrorShutdown)
  }

  private def launchApp(
    clientAssertionValidator: ClientAssertionValidator,
    interopTokenGenerator: InteropTokenGenerator
  ): Future[Http.ServerBinding] = {
    Kamon.init()

    locally {
      AkkaManagement.get(classicActorSystem).start()
    }

    val authApiService: AuthApiService       =
      AuthApiServiceImpl(authorizationManagementService, clientAssertionValidator, interopTokenGenerator)
    val authApiMarshaller: AuthApiMarshaller = AuthApiMarshallerImpl

    val authApi: AuthApi = new AuthApi(
      authApiService,
      authApiMarshaller,
      SecurityDirectives.authenticateOAuth2("SecurityRealm", PassThroughAuthenticator)
    )

    val healthApi: HealthApi = new HealthApi(
      new HealthServiceApiImpl(),
      HealthApiMarshallerImpl,
      SecurityDirectives.authenticateOAuth2("SecurityRealm", PassThroughAuthenticator)
    )

    val controller: Controller = new Controller(
      authApi,
      healthApi,
      validationExceptionToRoute = Some(report => {
        val error =
          problemOf(
            StatusCodes.BadRequest,
            ValidationRequestError(OpenapiUtils.errorFromRequestValidationReport(report))
          )
        complete(error.status, error)(AuthApiMarshallerImpl.toEntityMarshallerProblem)
      })
    )

    val server: Future[Http.ServerBinding] =
      Http().newServerAt("0.0.0.0", ApplicationConfiguration.serverPort).bind(corsHandler(controller.routes))

    server
  }
}
