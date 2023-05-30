package it.pagopa.interop.clientassertionvalidation

object SpecUtil {

  val successfulJwtValidator: ClientAssertionValidator =
    new NimbusClientAssertionValidator(Set(SpecData.clientAssertionAudience))

  val failureJwtValidator: ClientAssertionValidator =
    new NimbusClientAssertionValidator(Set("another-audience"))

}
