package it.pagopa.interop.authorizationserver

import akka.actor
import akka.actor.testkit.typed.scaladsl.{ActorTestKit, ScalaTestWithActorTestKit}
import akka.actor.typed.ActorSystem
import akka.actor.typed.scaladsl.Behaviors
import akka.http.scaladsl.Http
import akka.http.scaladsl.server.directives.SecurityDirectives
import it.pagopa.interop.authorizationserver.SpecConfiguration._
import it.pagopa.interop.authorizationserver.api.{AuthApi, HealthApi}
import it.pagopa.interop.authorizationserver.api.impl.{
  AuthApiMarshallerImpl,
  AuthApiServiceImpl,
  HealthApiMarshallerImpl,
  HealthServiceApiImpl
}
import it.pagopa.interop.authorizationserver.server.Controller
import it.pagopa.interop.authorizationserver.service.AuthorizationManagementService
import it.pagopa.interop.commons.jwt.service.{ClientAssertionValidator, InteropTokenGenerator}
import org.scalamock.scalatest.MockFactory
import it.pagopa.interop.commons.utils.AkkaUtils.PassThroughAuthenticator

import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContextExecutor, Future}

class BaseSpec extends ScalaTestWithActorTestKit(SpecConfiguration.config) with MockFactory {

  var controller: Option[Controller] = None

  var bindServer: Option[Future[Http.ServerBinding]] = None

  val httpSystem: ActorSystem[Any]                        =
    ActorSystem(Behaviors.ignore[Any], name = system.name, config = system.settings.config)
  implicit val executionContext: ExecutionContextExecutor = httpSystem.executionContext
  implicit val classicSystem: actor.ActorSystem           = httpSystem.classicSystem

  val mockClientAssertionValidator: ClientAssertionValidator             = mock[ClientAssertionValidator]
  val mockInteropTokenGenerator: InteropTokenGenerator                   = mock[InteropTokenGenerator]
  val mockAuthorizationManagementService: AuthorizationManagementService = mock[AuthorizationManagementService]

  def startServer(controller: Controller): Http.ServerBinding = {
    bindServer = Some(
      Http()
        .newServerAt("0.0.0.0", servicePort)
        .bind(controller.routes)
    )

    Await.result(bindServer.get, 100.seconds)
  }

  def shutDownServer(): Unit = {
    bindServer.foreach(_.foreach(_.unbind()))
    ActorTestKit.shutdown(httpSystem, 5.seconds)
  }

  override def beforeAll(): Unit = {

    val authApi =
      new AuthApi(
        AuthApiServiceImpl(
          authorizationManagementService = mockAuthorizationManagementService,
          jwtValidator = mockClientAssertionValidator,
          interopTokenGenerator = mockInteropTokenGenerator
        ),
        AuthApiMarshallerImpl,
        SecurityDirectives.authenticateOAuth2("SecurityRealm", PassThroughAuthenticator)
      )

    val healthApi: HealthApi = new HealthApi(
      new HealthServiceApiImpl(),
      HealthApiMarshallerImpl,
      SecurityDirectives.authenticateOAuth2("SecurityRealm", PassThroughAuthenticator)
    )

    controller = Some(new Controller(authApi, healthApi))

    controller.foreach(startServer)
  }

  override def afterAll(): Unit = {
    shutDownServer()
    super.afterAll()
  }

}
