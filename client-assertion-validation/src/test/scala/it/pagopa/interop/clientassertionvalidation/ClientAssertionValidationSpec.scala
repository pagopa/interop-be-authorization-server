package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.SpecData._
import it.pagopa.interop.clientassertionvalidation.SpecUtil._
import it.pagopa.interop.clientassertionvalidation.Validation._
import it.pagopa.interop.commons.jwt.errors._
import org.scalatest.matchers.should.Matchers._
import org.scalatest.wordspec.AnyWordSpecLike

import java.util.UUID

class ClientAssertionValidationSpec extends AnyWordSpecLike {

  "Client Assertion Validation" should {
    "fail on wrong client assertion type" in {
      val wrongClientAssertionType = "something-wrong"

      validateClientAssertion(Some(clientId.toString), validClientAssertion, wrongClientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(
        InvalidAssertion(
          InvalidClientAssertionType(s"Client assertion type '$wrongClientAssertionType' is not valid").getMessage
        )
      )
    }

    "fail on wrong grant type" in {
      val wrongGrantType = "something-wrong"

      validateClientAssertion(Some(clientId.toString), validClientAssertion, clientAssertionType, wrongGrantType)(
        successfulJwtValidator
      ) shouldBe Left(InvalidAssertion(InvalidGrantType(wrongGrantType).getMessage))
    }

    "fail on malformed assertion" in {
      val malformedAssertion = "something-wrong"

      validateClientAssertion(Some(clientId.toString), malformedAssertion, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(InvalidAssertion("Invalid serialized unsecured/JWS/JWE object: Missing part delimiters"))
    }

    "fail on wrong audience in assertion" in {
      validateClientAssertion(Some(clientId.toString), validClientAssertion, clientAssertionType, grantType)(
        failureJwtValidator
      ) shouldBe Left(InvalidAssertion("JWT audience rejected: [test.interop.pagopa.it]"))
    }

    "fail if client ID in the assertion is different from the parameter client ID" in {
      val wrongClientId = UUID.randomUUID().toString
      validateClientAssertion(Some(wrongClientId), validClientAssertion, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(InvalidAssertion(InvalidSubject(clientId.toString).getMessage))
    }

    "fail on wrong client id format" in {
      val wrongClientId = "definitely-not-an-uuid"
      validateClientAssertion(Some(wrongClientId), validClientAssertion, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(InvalidClientIdFormat(wrongClientId))
    }

    "fail on wrong jwt subject format" in {
      validateClientAssertion(Some(clientId.toString), clientAssertionWithWrongSubject, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(InvalidAssertion(InvalidSubjectFormat("definitely-not-an-uuid").getMessage))
    }

    "fail on wrong purpose id format" in {
      validateClientAssertion(
        Some(clientId.toString),
        clientAssertionWithWrongPurposeId,
        clientAssertionType,
        grantType
      )(successfulJwtValidator) shouldBe Left(
        InvalidAssertion(InvalidPurposeIdFormat("definitely-not-an-uuid").getMessage)
      )
    }

    "succeed on correct client assertion" in {
      validateClientAssertion(Some(clientId.toString), validClientAssertion, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe a[Right[_, _]]
    }
  }

}
