package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.authorizationmanagement.client.model.{ClientComponentState, ClientKind}
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.SpecData._
import it.pagopa.interop.clientassertionvalidation.SpecUtil._
import it.pagopa.interop.clientassertionvalidation.Validation._
import org.scalatest.matchers.should.Matchers._
import org.scalatest.wordspec.AnyWordSpecLike

class PlatformStateValidation extends AnyWordSpecLike {

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
