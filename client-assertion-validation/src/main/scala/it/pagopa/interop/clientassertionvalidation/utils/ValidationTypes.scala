package it.pagopa.interop.clientassertionvalidation.utils

import it.pagopa.interop.clientassertionvalidation.Errors.{
  ClientAssertionSignatureVerificationFailure,
  ClientAssertionValidationError,
  ClientAssertionValidationFailure,
  PlatformStateVerificationFailure
}

private[clientassertionvalidation] object ValidationTypes {
  type ValidationFailure            = ClientAssertionValidationError with ClientAssertionValidationFailure
  type SignatureVerificationFailure = ClientAssertionValidationError with ClientAssertionSignatureVerificationFailure
  type StatesVerificationFailure    = ClientAssertionValidationError with PlatformStateVerificationFailure

}
