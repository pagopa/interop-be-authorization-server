package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID

object Errors {

  final case class PurposeNotFound(clientId: UUID, purposeId: UUID)
      extends ComponentError("0003", s"Purpose $purposeId not found for client $clientId")

//  final case class InactivePlatformState(clientId: UUID, errorMessages: List[String])
//      extends ComponentError("0004", s"Non-active state for Client $clientId: ${errorMessages.mkString(", ")}")
  final case class InactivePlatformState(clientId: UUID, reasons: ComponentError*)
      extends ComponentError(
        "0004",
        s"Non-active state for Client $clientId: ${reasons.map(_.getMessage).mkString(", ")}"
      )

  final case class InactivePurpose(state: String)   extends ComponentError("0005", s"Purpose is in state $state")
  final case class InactiveEService(state: String)  extends ComponentError("0006", s"E-Service is in state $state")
  final case class InactiveAgreement(state: String) extends ComponentError("0007", s"Agreement is in state $state")

  final case object PurposeIdNotProvided
      extends ComponentError("0009", "Claim purposeId does not exist in this assertion")

  // TODO This may be too generic
  final case class InvalidAssertion(message: String)
      extends ComponentError("0010", s"Invalid client assertion. Reasons: $message")

  final case class InvalidAssertionSignature(clientId: UUID, kid: String, reason: String)
      extends ComponentError(
        "0012",
        s"Invalid assertion signature for request with client $clientId and kid $kid. Reason: $reason"
      )

  final case class InvalidClientIdFormat(clientId: String)
      extends ComponentError("0013", s"Client id $clientId is not a valid UUID")

}
