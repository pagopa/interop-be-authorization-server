package it.pagopa.interop.authorizationserver.model

import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import spray.json._

final case class ClientAssertionDetails(
  jwtId: String,
  issuedAt: Long,
  algorithm: String,
  keyId: String,
  issuer: String,
  subject: String,
  audience: String,
  expirationTime: Long
)

object ClientAssertionDetails extends SprayJsonSupport with DefaultJsonProtocol {
  implicit val assertionDetailsMessageFormat: RootJsonFormat[ClientAssertionDetails] =
    jsonFormat8(ClientAssertionDetails.apply)
}
