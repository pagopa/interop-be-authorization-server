package it.pagopa.interop.authorizationserver.error

import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID

object AuthServerErrors {

  final case object Forbidden extends ComponentError("0001", s"The user has no access to the requested resource")
  final case object InternalServerError extends ComponentError("0002", "There was an internal server error")

  final case class PurposeNotFound(clientId: UUID, purposeId: UUID)
      extends ComponentError("0003", s"Purpose $purposeId not found for client $clientId")

  final case class InactiveClient(clientId: UUID, errorMessages: List[String])
      extends ComponentError("0004", s"Client $clientId is inactive: ${errorMessages.mkString(", ")}")
  final case class InactivePurpose(state: String)   extends ComponentError("0005", s"Purpose is in state $state")
  final case class InactiveEService(state: String)  extends ComponentError("0006", s"E-Service is in state $state")
  final case class InactiveAgreement(state: String) extends ComponentError("0007", s"Agreement is in state $state")

  final object CreateTokenRequestError
      extends ComponentError("0008", s"A token cannot be generated for the given request")

  final case object PurposeIdNotProvided
      extends ComponentError("0009", "purposeId claim does not exist in this assertion")

}
