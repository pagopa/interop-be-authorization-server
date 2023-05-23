package it.pagopa.interop.clientassertionvalidation

import com.nimbusds.jwt.SignedJWT

final case class AssertionValidationResult(clientAssertion: ClientAssertion, jwt: SignedJWT)
