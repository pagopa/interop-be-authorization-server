package it.pagopa.interop.clientassertionvalidation

import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import it.pagopa.interop.clientassertionvalidation.SpecData.{
  clientAssertionType,
  clientId,
  grantType,
  validClientAssertion
}
import it.pagopa.interop.clientassertionvalidation.Validation.validateClientAssertion
import it.pagopa.interop.commons.jwt.model.ClientAssertionChecker
import it.pagopa.interop.commons.jwt.service.ClientAssertionValidator
import it.pagopa.interop.commons.jwt.service.impl.{DefaultClientAssertionValidator, getClaimsVerifier}
import it.pagopa.interop.commons.jwt.{KID, PublicKeysHolder, SerializedKey}
import org.scalatest.Assertions.fail

object SpecUtil {

  val successfulJwtValidator: ClientAssertionValidator = new DefaultClientAssertionValidator with PublicKeysHolder {
    var publicKeyset: Map[KID, SerializedKey]                                        = Map.empty
    override protected val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
      getClaimsVerifier(audience = Set(SpecData.clientAssertionAudience))
  }

  val failureJwtValidator: ClientAssertionValidator = new DefaultClientAssertionValidator with PublicKeysHolder {
    var publicKeyset: Map[KID, SerializedKey]                                        = Map.empty
    override protected val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
      getClaimsVerifier(audience = Set("another-audience"))
  }

  val validChecker: ClientAssertionChecker =
    validateClientAssertion(Some(clientId.toString), validClientAssertion, clientAssertionType, grantType)(
      successfulJwtValidator
    ).getOrElse(fail("Error generating checker in test"))

}
