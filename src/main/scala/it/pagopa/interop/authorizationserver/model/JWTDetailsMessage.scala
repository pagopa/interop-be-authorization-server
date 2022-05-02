package it.pagopa.interop.authorizationserver.model

import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import spray.json._

final case class JWTDetailsMessage(
  jti: String,
  iat: Long,
  exp: Long,
  nbf: Long,
  organizationId: String,
  clientId: String,
  purposeId: Option[String],
  kid: String
) {
  def readableString: String =
    s"jti: $jti / iat: $iat / exp: $exp / nbf: $nbf / organizationId: $organizationId / clientId: $clientId / kid: $kid / purposeId: $purposeId"
}

object JWTDetailsMessage extends SprayJsonSupport with DefaultJsonProtocol {
  implicit val jwtDetailsMessageFormat: RootJsonFormat[JWTDetailsMessage] = jsonFormat8(JWTDetailsMessage.apply)
}
