package it.pagopa.interop.authorizationserver.error

import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID

object AuthServerErrors {

  final object CreateTokenRequestError
      extends ComponentError("0008", s"Unable to generate a token for the given request")

  final case class KeyNotFound(clientId: UUID, kid: String)
      extends ComponentError("0011", s"Key $kid not found for Client $clientId")

}
