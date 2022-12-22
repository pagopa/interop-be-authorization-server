package it.pagopa.interop.authorizationserver.error

import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID

object AuthServerErrors {

  final case class PurposeNotFound(clientId: UUID, purposeId: UUID)
      extends ComponentError("0003", s"Purpose $purposeId not found for client $clientId")

  final case class InactiveClient(clientId: UUID, errorMessages: List[String])
      extends ComponentError("0004", s"Client $clientId is inactive: ${errorMessages.mkString(", ")}")
  final case class InactivePurpose(state: String)   extends ComponentError("0005", s"Purpose is in state $state")
  final case class InactiveEService(state: String)  extends ComponentError("0006", s"E-Service is in state $state")
  final case class InactiveAgreement(state: String) extends ComponentError("0007", s"Agreement is in state $state")

  final object CreateTokenRequestError
      extends ComponentError("0008", s"Unable to generate a token for the given request")

  final case object PurposeIdNotProvided
      extends ComponentError("0009", "Claim purposeId does not exist in this assertion")

  final case class InvalidAssertion(message: String)
      extends ComponentError("0010", s"Invalid client assertion. Reasons: $message")

  final case class KeyNotFound(clientId: UUID, kid: String)
      extends ComponentError("0011", s"Key $kid not found for Client $clientId")

  final case class InvalidAssertionSignature(clientId: UUID, kid: String, reason: String)
      extends ComponentError(
        "0012",
        s"Invalid assertion signature for request with client $clientId and kid $kid. Reason: $reason"
      )
}
