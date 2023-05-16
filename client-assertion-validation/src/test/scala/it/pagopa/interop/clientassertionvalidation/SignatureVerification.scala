package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.SpecData._
import it.pagopa.interop.clientassertionvalidation.SpecUtil._
import it.pagopa.interop.clientassertionvalidation.Validation._
import org.scalatest.matchers.should.Matchers._
import org.scalatest.wordspec.AnyWordSpecLike

class SignatureVerification extends AnyWordSpecLike {

  "Client Assertion Signature Verification" should {

    "fail if the assertion is not signed with the public key corresponding to the kid" in {
      verifyClientAssertionSignature(keyWithClient.copy(key = anotherModelKey), validChecker) shouldBe Left(
        InvalidAssertionSignature(keyWithClient.client.id, validChecker.kid, "Invalid JWT signature")
      )
    }

    "succeed on correctly signed client assertion" in {
      verifyClientAssertionSignature(keyWithClient, validChecker) shouldBe Right(())
    }

  }

}
