package it.pagopa.interop.authorizationserver.server.impl

import cats.syntax.all._
import akka.http.scaladsl.Http
import akka.management.scaladsl.AkkaManagement
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.server.Controller

import it.pagopa.interop.commons.utils.CORSSupport
import kamon.Kamon
import com.typesafe.scalalogging.Logger

import scala.util.{Failure, Success}
import akka.actor.typed.ActorSystem
import akka.actor.typed.scaladsl.Behaviors
import buildinfo.BuildInfo
import akka.actor.typed.DispatcherSelector
import scala.concurrent.ExecutionContextExecutor

object Main extends App with CORSSupport with Dependencies {

  val logger: Logger = Logger(this.getClass)

  System.setProperty("kanela.show-banner", "false")

  val system: ActorSystem[Nothing] = ActorSystem[Nothing](
    Behaviors.setup[Nothing] { context =>
      implicit val actorSystem: ActorSystem[_]          = context.system
      val selector: DispatcherSelector                  = DispatcherSelector.fromConfig("futures-dispatcher")
      implicit val blockingEc: ExecutionContextExecutor = actorSystem.dispatchers.lookup(selector)

      Kamon.init()
      AkkaManagement.get(actorSystem.classicSystem).start()

      val serverBinding = for {
        clientAssertionValidator <- getClientAssertionValidator()
        controller: Controller = new Controller(
          authApi(clientAssertionValidator),
          healthApi,
          validationExceptionToRoute.some
        )(actorSystem.classicSystem)
        binding <- Http()
          .newServerAt("0.0.0.0", ApplicationConfiguration.serverPort)
          .bind(corsHandler(controller.routes))
      } yield binding

      serverBinding.onComplete {
        case Success(b) =>
          logger.info(s"Started server at ${b.localAddress.getHostString()}:${b.localAddress.getPort()}")
        case Failure(e) =>
          actorSystem.terminate()
          logger.error("Startup error: ", e)
      }

      Behaviors.empty[Nothing]
    },
    BuildInfo.name
  )

  system.whenTerminated.onComplete { case _ => Kamon.stop() }(scala.concurrent.ExecutionContext.global)

}
