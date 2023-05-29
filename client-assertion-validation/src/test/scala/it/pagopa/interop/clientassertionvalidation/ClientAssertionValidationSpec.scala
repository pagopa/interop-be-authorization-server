package it.pagopa.interop.clientassertionvalidation

import cats.data.NonEmptyList
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.SpecData._
import it.pagopa.interop.clientassertionvalidation.SpecUtil._
import it.pagopa.interop.clientassertionvalidation.Validation._
import org.scalatest.matchers.should.Matchers._
import org.scalatest.wordspec.AnyWordSpecLike

import java.util.UUID

class ClientAssertionValidationSpec extends AnyWordSpecLike {

  "Client Assertion Validation" should {
    "fail on wrong client assertion type" in {
      val wrongClientAssertionType = "something-wrong"

      validateClientAssertion(Some(clientId.toString), validClientAssertion, wrongClientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidAssertionType(wrongClientAssertionType)))
    }

    "fail on wrong grant type" in {
      val wrongGrantType = "something-wrong"

      validateClientAssertion(Some(clientId.toString), validClientAssertion, clientAssertionType, wrongGrantType)(
        successfulJwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidGrantType(wrongGrantType)))
    }

    "fail on malformed assertion" in {
      val malformedAssertion = "something-wrong"

      validateClientAssertion(Some(clientId.toString), malformedAssertion, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(
        NonEmptyList
          .one(ClientAssertionParseFailed("Invalid serialized unsecured/JWS/JWE object: Missing part delimiters"))
      )
    }

    "fail on wrong audience in assertion" in {
      validateClientAssertion(Some(clientId.toString), validClientAssertion, clientAssertionType, grantType)(
        failureJwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidAudiences(Set("test.interop.pagopa.it"))))
    }

    "fail if client ID in the assertion is different from the parameter client ID" in {
      val wrongClientId = UUID.randomUUID().toString
      validateClientAssertion(Some(wrongClientId), validClientAssertion, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidSubject(clientId.toString)))
    }

    "fail on wrong client id format" in {
      val wrongClientId = "definitely-not-an-uuid"
      validateClientAssertion(Some(wrongClientId), validClientAssertion, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidClientIdFormat(wrongClientId)))
    }

    "fail on wrong jwt subject format" in {
      validateClientAssertion(Some(clientId.toString), clientAssertionWithWrongSubject, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidSubjectFormat("definitely-not-an-uuid")))
    }

    "fail on wrong purpose id format" in {
      validateClientAssertion(
        Some(clientId.toString),
        clientAssertionWithWrongPurposeId,
        clientAssertionType,
        grantType
      )(successfulJwtValidator) shouldBe Left(NonEmptyList.one(InvalidPurposeIdFormat("definitely-not-an-uuid")))
    }

    "fail on multiple validation errors" in {
      val wrongClientId = UUID.randomUUID().toString
      validateClientAssertion(Some(wrongClientId), clientAssertionWithWrongPurposeId, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe Left(
        NonEmptyList.of(InvalidSubject(clientId.toString), InvalidPurposeIdFormat("definitely-not-an-uuid"))
      )
    }

    "succeed on correct client assertion" in {
      validateClientAssertion(Some(clientId.toString), validClientAssertion, clientAssertionType, grantType)(
        successfulJwtValidator
      ) shouldBe a[Right[_, _]]
    }
  }

}
