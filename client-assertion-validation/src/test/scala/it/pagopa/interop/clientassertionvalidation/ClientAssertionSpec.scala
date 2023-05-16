package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.authorizationmanagement.client.model.{ClientComponentState, ClientKind}
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.SpecData._
import it.pagopa.interop.clientassertionvalidation.SpecUtil._
import it.pagopa.interop.clientassertionvalidation.Validation._
import it.pagopa.interop.commons.jwt.errors._
import org.scalatest.matchers.should.Matchers._
import org.scalatest.wordspec.AnyWordSpecLike

import java.util.UUID

class ClientAssertionSpec extends AnyWordSpecLike {

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

// TODO Cannot be done right now (the call is external to the module)

//    "fail if kid in the assertion is not found for the given client ID" in {
//      (mockAuthorizationManagementService
//        .getKeyWithClient(_: UUID, _: String)(_: Seq[(String, String)]))
//        .expects(clientId, clientAssertionKid, *)
//        .once()
//        .returns(Future.failed(KeyNotFound(clientId, clientAssertionKid)))
//
//      Get() ~> service.createToken(
//        Some(clientId.toString),
//        validClientAssertion,
//        clientAssertionType,
//        grantType
//      ) ~> check {
//        status shouldEqual StatusCodes.BadRequest
//      }
//    }

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

  "Platform State Verification" should {

    "fail if purpose id is not assigned to the client" in {
      verifyPlatformState(activeClient.copy(purposes = Seq.empty), validChecker) shouldBe Left(
        PurposeNotFound(validChecker.subject, validChecker.purposeId.get)
      )
    }

    "fail if Purpose is not active" in {
      val client = makeClient(purposeState = ClientComponentState.INACTIVE)
      verifyPlatformState(client, validChecker) shouldBe Left(
        InactivePlatformState(client.id, InactivePurpose(ClientComponentState.INACTIVE.toString))
      )
    }

    "fail if EService is not active" in {
      val client = makeClient(eServiceState = ClientComponentState.INACTIVE)
      verifyPlatformState(client, validChecker) shouldBe Left(
        InactivePlatformState(client.id, InactiveEService(ClientComponentState.INACTIVE.toString))
      )
    }

    "fail if Agreement is not active" in {
      val client = makeClient(agreementState = ClientComponentState.INACTIVE)
      verifyPlatformState(client, validChecker) shouldBe Left(
        InactivePlatformState(client.id, InactiveAgreement(ClientComponentState.INACTIVE.toString))
      )
    }

    "fail if several objects are not active" in {
      val client = makeClient(
        purposeState = ClientComponentState.INACTIVE,
        eServiceState = ClientComponentState.INACTIVE,
        agreementState = ClientComponentState.INACTIVE
      )
      verifyPlatformState(client, validChecker) shouldBe Left(
        InactivePlatformState(
          client.id,
          InactivePurpose(ClientComponentState.INACTIVE.toString),
          InactiveEService(ClientComponentState.INACTIVE.toString),
          InactiveAgreement(ClientComponentState.INACTIVE.toString)
        )
      )
    }

    "succeed on correct Consumer client configurations" in {
      val consumerClient = activeClient
      verifyPlatformState(consumerClient, validChecker) shouldBe Right(())
    }

    "succeed on API client" in {
      val apiClient = makeClient(kind = ClientKind.API).copy(purposes = Seq.empty)
      verifyPlatformState(apiClient, validChecker) shouldBe Right(())
    }

  }
}
