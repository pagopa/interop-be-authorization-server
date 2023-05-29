package it.pagopa.interop.clientassertionvalidation

import cats.data.NonEmptyList
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.SpecData._
import it.pagopa.interop.clientassertionvalidation.SpecUtil._
import it.pagopa.interop.clientassertionvalidation.Validation._
import org.scalatest.matchers.should.Matchers._
import org.scalatest.wordspec.AnyWordSpecLike

class SignatureVerification extends AnyWordSpecLike {

  "Client Assertion Signature Verification" should {

    val successfulValidation: Either[NonEmptyList[ClientAssertionValidationError], AssertionValidationResult] =
      validateClientAssertion(Some(clientId.toString), validClientAssertion, clientAssertionType, grantType)(
        successfulJwtValidator
      )

    "fail if the assertion is not signed with the public key corresponding to the kid" in {
      val result = for {
        validation <- successfulValidation
        _          <- verifyClientAssertionSignature(keyWithClient.copy(key = anotherModelKey), validation)(
          successfulJwtValidator
        )
      } yield ()

      result shouldBe Left(InvalidClientAssertionSignature)
    }

    "succeed on correctly signed client assertion" in {
      val result = for {
        validation <- successfulValidation
        _          <- verifyClientAssertionSignature(keyWithClient, validation)(successfulJwtValidator)
      } yield ()

      result shouldBe Right(())
    }

  }

}
