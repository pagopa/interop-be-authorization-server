package it.pagopa.interop.authorizationserver

import akka.http.scaladsl.Http
import akka.http.scaladsl.model.{HttpMethods, HttpRequest, StatusCodes}
import it.pagopa.interop.authorizationserver.utils.{BaseRunningServerSpec, SpecConfiguration}

class ApplicationUrlSpec extends BaseRunningServerSpec {

  "the application url" should {
    "not contain the interface version" in {

      val response = Http()
        .singleRequest(
          HttpRequest(
            uri = s"http://0.0.0.0:${SpecConfiguration.servicePort}/authorization-server/status",
            method = HttpMethods.GET
          )
        )
        .futureValue

      response.status shouldBe StatusCodes.OK

    }
  }
}
