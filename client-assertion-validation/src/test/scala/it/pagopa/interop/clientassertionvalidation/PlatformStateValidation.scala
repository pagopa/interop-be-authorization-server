package it.pagopa.interop.clientassertionvalidation

import cats.data.NonEmptyList
import it.pagopa.interop.authorizationmanagement.client.model.{ClientComponentState, ClientKind}
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.SpecData._
import it.pagopa.interop.clientassertionvalidation.SpecUtil._
import it.pagopa.interop.clientassertionvalidation.Validation._
import it.pagopa.interop.clientassertionvalidation.model._
import it.pagopa.interop.commons.utils.PURPOSE_ID_CLAIM
import org.scalatest.matchers.should.Matchers._
import org.scalatest.wordspec.AnyWordSpecLike

class PlatformStateValidation extends AnyWordSpecLike {

  "Platform State Verification" should {

    val assertion = fastClientAssertionJWT(customClaims = Map(PURPOSE_ID_CLAIM -> SpecData.purposeId))
    val successfulValidation: Either[NonEmptyList[ClientAssertionValidationError], AssertionValidationResult] =
      validateClientAssertion(Some(clientId.toString), assertion, clientAssertionType, grantType)(jwtValidator)

    "fail if purpose id is not assigned to the client" in {
      val result = for {
        validation <- successfulValidation
        _          <- verifyPlatformState(activeClient.copy(purposes = Seq.empty), validation.clientAssertion)
      } yield ()

      result shouldBe Left(NonEmptyList.one(PurposeNotFound(SpecData.clientId, SpecData.purposeId)))
    }

    "fail if Purpose is not active" in {
      val client = makeClient(purposeState = ClientComponentState.INACTIVE)

      val result = for {
        validation <- successfulValidation
        _          <- verifyPlatformState(client, validation.clientAssertion)
      } yield ()

      result shouldBe Left(NonEmptyList.one(InactivePurpose))
    }

    "fail if EService is not active" in {
      val client = makeClient(eServiceState = ClientComponentState.INACTIVE)

      val result = for {
        validation <- successfulValidation
        _          <- verifyPlatformState(client, validation.clientAssertion)
      } yield ()

      result shouldBe Left(NonEmptyList.one(InactiveEService))
    }

    "fail if Agreement is not active" in {
      val client = makeClient(agreementState = ClientComponentState.INACTIVE)

      val result = for {
        validation <- successfulValidation
        _          <- verifyPlatformState(client, validation.clientAssertion)
      } yield ()

      result shouldBe Left(NonEmptyList.one(InactiveAgreement))
    }

    "fail if several objects are not active" in {
      val client = makeClient(
        purposeState = ClientComponentState.INACTIVE,
        eServiceState = ClientComponentState.INACTIVE,
        agreementState = ClientComponentState.INACTIVE
      )

      val result = for {
        validation <- successfulValidation
        _          <- verifyPlatformState(client, validation.clientAssertion)
      } yield ()

      result shouldBe Left(NonEmptyList.of(InactivePurpose, InactiveEService, InactiveAgreement))

    }

    "succeed on correct Consumer client configurations" in {
      val consumerClient = activeClient

      val result = for {
        validation <- successfulValidation
        _          <- verifyPlatformState(consumerClient, validation.clientAssertion)
      } yield ()

      result shouldBe Right(())
    }

    "succeed on API client" in {
      val apiClient = makeClient(kind = ClientKind.API).copy(purposes = Seq.empty)

      val result = for {
        validation <- successfulValidation
        _          <- verifyPlatformState(apiClient, validation.clientAssertion)
      } yield ()

      result shouldBe Right(())
    }

  }
}
