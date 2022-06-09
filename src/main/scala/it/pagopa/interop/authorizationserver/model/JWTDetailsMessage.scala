package it.pagopa.interop.authorizationserver.model

import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import spray.json._

final case class JWTDetailsMessage(
  jwtId: String,
  issuedAt: Long,
  clientId: String,
  organizationId: String,
  agreementId: String,
  eserviceId: String,
  descriptorId: String,
  purposeId: String,
  purposeVersionId: String,
  algorithm: String,
  keyId: String,
  audience: String,
  subject: String,
  notBefore: Long,
  expirationTime: Long,
  issuer: String,
  clientAssertion: ClientAssertionDetails
) {
  def readableString: String = ""
//    s"jti: $jti / iat: $iat / exp: $exp / nbf: $nbf / organizationId: $organizationId / clientId: $clientId / kid: $kid / purposeId: $purposeId"
}

object JWTDetailsMessage extends SprayJsonSupport with DefaultJsonProtocol {
  implicit val jwtDetailsMessageFormat: RootJsonFormat[JWTDetailsMessage] = jsonFormat17(JWTDetailsMessage.apply)
}
