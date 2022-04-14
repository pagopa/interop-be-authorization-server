package it.pagopa.interop.authorizationserver.api

import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import akka.http.scaladsl.model.StatusCode
import it.pagopa.interop.authorizationserver.model._
import it.pagopa.interop.commons.utils.errors.ComponentError
import spray.json.{DefaultJsonProtocol, RootJsonFormat}

package object impl extends SprayJsonSupport with DefaultJsonProtocol {
  implicit val problemErrorFormat: RootJsonFormat[ProblemError] = jsonFormat2(ProblemError)
  implicit val problemFormat: RootJsonFormat[Problem]           = jsonFormat5(Problem)

  implicit val clientCredentialsResponseFormat: RootJsonFormat[ClientCredentialsResponse] =
    jsonFormat3(ClientCredentialsResponse)

  final val serviceErrorCodePrefix: String = "015"
  final val defaultProblemType: String     = "about:blank"

  def problemOf(httpError: StatusCode, error: ComponentError, defaultMessage: String = "Unknown error"): Problem =
    Problem(
      `type` = defaultProblemType,
      status = httpError.intValue,
      title = httpError.defaultMessage,
      errors = Seq(
        ProblemError(
          code = s"$serviceErrorCodePrefix-${error.code}",
          detail = Option(error.getMessage).getOrElse(defaultMessage)
        )
      )
    )

}
