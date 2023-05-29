package it.pagopa.interop.clientassertionvalidation

object SpecUtil {

//  val successfulJwtValidator: ClientAssertionValidator = new DefaultClientAssertionValidator with PublicKeysHolder {
//    var publicKeyset: Map[KID, SerializedKey]                                        = Map.empty
//    override protected val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
//      getClaimsVerifier(audience = Set(SpecData.clientAssertionAudience))
//  }
//
//  val failureJwtValidator: ClientAssertionValidator = new DefaultClientAssertionValidator with PublicKeysHolder {
//    var publicKeyset: Map[KID, SerializedKey]                                        = Map.empty
//    override protected val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
//      getClaimsVerifier(audience = Set("another-audience"))
//  }
//
//  val validChecker: ClientAssertionChecker =
//    validateClientAssertion(Some(clientId.toString), validClientAssertion, clientAssertionType, grantType)(
//      successfulJwtValidator
//    ).getOrElse(fail("Error generating checker in test"))

  val successfulJwtValidator: ClientAssertionValidator =
    new NimbusClientAssertionValidator(Set(SpecData.clientAssertionAudience))

  val failureJwtValidator: ClientAssertionValidator =
    new NimbusClientAssertionValidator(Set("another-audience"))

}
