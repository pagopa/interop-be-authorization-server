package it.pagopa.interop.authorizationserver.error

import cats.data.NonEmptyList
import it.pagopa.interop.clientassertionvalidation.Errors.ClientAssertionValidationError
import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID

object AuthServerErrors {

  final case class ClientAssertionValidationWrapper(errors: NonEmptyList[ClientAssertionValidationError])
      extends ComponentError("0001", errors.toList.mkString(","))

  final object CreateTokenRequestError
      extends ComponentError("0008", s"Unable to generate a token for the given request")

  final case class KeyNotFound(clientId: UUID, kid: String)
      extends ComponentError("0011", s"Key $kid not found for Client $clientId")

}
