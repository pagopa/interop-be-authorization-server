package it.pagopa.interop.clientassertionvalidation.model

import com.nimbusds.jwt.SignedJWT

final case class AssertionValidationResult(clientAssertion: ClientAssertion, jwt: SignedJWT)
