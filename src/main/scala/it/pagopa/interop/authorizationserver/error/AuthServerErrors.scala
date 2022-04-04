package it.pagopa.interop.authorizationserver.error

import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID

object AuthServerErrors {

  final case object Forbidden extends ComponentError("0001", s"The user has no access to the requested resource")
  final case object InternalServerError extends ComponentError("0002", "There was an internal server error")

  final case class PurposeNotFound(clientId: UUID, purposeId: UUID)
      extends ComponentError("0009", s"Purpose $purposeId not found for client $clientId")

  final case class InactiveClient(clientId: UUID, errorMessages: List[String])
      extends ComponentError("0010", s"Client $clientId is inactive: ${errorMessages.mkString(", ")}")

  final case class CreateTokenRequestError(error: String)
      extends ComponentError("0011", s"Error while creating a token for this request - $error")

  final case class MissingActivePurposeVersion(purposeId: UUID)
      extends ComponentError("0012", s"There is no active version for purpose $purposeId")

  final case class MissingActivePurposesVersions(purposesIds: Seq[UUID])
      extends ComponentError("0013", s"There is no active version for purposes ${purposesIds.mkString(", ")}")

  final case object PurposeIdNotProvided
      extends ComponentError("0017", "purposeId claim does not exist in this assertion")

  final case class InactivePurpose(state: String)   extends ComponentError("0014", s"Purpose is in state $state")
  final case class InactiveEservice(state: String)  extends ComponentError("0015", s"E-Service is in state $state")
  final case class InactiveAgreement(state: String) extends ComponentError("0016", s"Agreement is in state $state")

}