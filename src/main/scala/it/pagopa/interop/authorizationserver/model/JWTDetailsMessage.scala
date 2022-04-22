package it.pagopa.interop.authorizationserver.model

import spray.json._
import spray.json.DefaultJsonProtocol._

final case class JWTDetailsMessage(
  jti: String,
  iat: Long,
  exp: Long,
  clientId: String,
  purposeId: Option[String],
  kid: String
) {
  val readableString: String =
    s"jti: $jti / iat: $iat / exp: $exp / clientId: $clientId / kid: $kid / purposeId: $purposeId"
}

object JWTDetailsMessage {
  implicit val jsonWriter: JsonWriter[JWTDetailsMessage] = new JsonWriter[JWTDetailsMessage] {
    override def write(obj: JWTDetailsMessage): JsValue = JsObject(
      "jti"       -> obj.jti.toJson,
      "iat"       -> obj.iat.toJson,
      "exp"       -> obj.exp.toJson,
      "clientId"  -> obj.clientId.toJson,
      "purposeId" -> obj.purposeId.toJson,
      "kid"       -> obj.kid.toJson
    )
  }
}
