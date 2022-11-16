package it.pagopa.interop.authorizationserver.model

import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import spray.json._

final case class JWTDetailsMessage(
  jwtId: String,
  // Correlation ID is mandatory, but it is defined as optional to avoid
  //  - deserialization failures of previous messages that lack this field
  //  - impacts on auditing caused by correlation id generation bugs
  correlationId: Option[String],
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
  def readableString: String = this.toJson.compactPrint
}

object JWTDetailsMessage extends SprayJsonSupport with DefaultJsonProtocol {
  implicit val jwtDetailsMessageFormat: RootJsonFormat[JWTDetailsMessage] = jsonFormat18(JWTDetailsMessage.apply)
}
