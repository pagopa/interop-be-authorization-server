package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID
import scala.util.control.NoStackTrace

object Errors {

  abstract class ClientAssertionValidationError(override val code: String, override val msg: String)
      extends ComponentError(code, msg)
      with NoStackTrace

  final case class PurposeNotFound(clientId: UUID, purposeId: UUID)
      extends ClientAssertionValidationError("0003", s"Purpose $purposeId not found for client $clientId")

  final case class InactivePlatformState(clientId: UUID, reasons: ClientAssertionValidationError*)
      extends ClientAssertionValidationError(
        "0004",
        s"Non-active state for Client $clientId: ${reasons.map(_.getMessage).mkString(", ")}"
      )

  final case class InactivePurpose(state: String)
      extends ClientAssertionValidationError("0005", s"Purpose is in state $state")
  final case class InactiveEService(state: String)
      extends ClientAssertionValidationError("0006", s"E-Service is in state $state")
  final case class InactiveAgreement(state: String)
      extends ClientAssertionValidationError("0007", s"Agreement is in state $state")

  final case object PurposeIdNotProvided
      extends ClientAssertionValidationError("0009", "Claim purposeId does not exist in this assertion")

  final case class InvalidAssertion(message: String)
      extends ClientAssertionValidationError("0010", s"Invalid client assertion. Reasons: $message")

  final case class InvalidAssertionSignature(clientId: UUID, kid: String, reason: String)
      extends ClientAssertionValidationError(
        "0012",
        s"Invalid assertion signature for request with client $clientId and kid $kid. Reason: $reason"
      )

  final case class InvalidClientIdFormat(clientId: String)
      extends ClientAssertionValidationError("0013", s"Client id $clientId is not a valid UUID")

}
