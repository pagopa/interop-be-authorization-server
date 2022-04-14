package it.pagopa.interop.authorizationserver

import akka.http.scaladsl.Http
import akka.http.scaladsl.model.{HttpMethods, HttpRequest, StatusCodes}
import org.scalatest.wordspec.AnyWordSpecLike

import scala.concurrent.Await
import scala.concurrent.duration._

class ApplicationUrlSpec extends BaseSpec with AnyWordSpecLike {

  "the application url" should {
    "not contain the interface version" in {

      val response = Await.result(
        Http().singleRequest(
          HttpRequest(
            uri = s"http://0.0.0.0:${SpecConfiguration.servicePort}/authorization-server/status",
            method = HttpMethods.GET
          )
        ),
        10.seconds
      )

      response.status shouldBe StatusCodes.OK

    }
  }
}
