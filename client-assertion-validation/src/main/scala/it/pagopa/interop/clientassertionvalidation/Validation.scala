package it.pagopa.interop.clientassertionvalidation

import cats.data.{NonEmptyList, Validated, ValidatedNel}
import cats.syntax.all._
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.model._
import it.pagopa.interop.clientassertionvalidation.utils.AuthorizationManagementUtils
import it.pagopa.interop.clientassertionvalidation.utils.ValidationTypes._
import it.pagopa.interop.commons.utils.TypeConversions._

import java.util.UUID

object Validation {

  type StatesValidationResult[A] = ValidatedNel[StatesVerificationFailure, A]

  private final val clientAssertionType: String        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  private final val clientCredentialsGrantType: String = "client_credentials"

  def validateClientAssertion(
    clientId: Option[String],
    clientAssertion: String,
    clientAssertionType: String,
    grantType: String
  )(jwtValidator: ClientAssertionValidator): Either[NonEmptyList[ValidationFailure], AssertionValidationResult] =
    for {
      clientUUID      <- clientId.traverse(id =>
        id.toUUID.toEither.leftMap(_ => NonEmptyList.one(InvalidClientIdFormat(id)))
      )
      _               <- validateRequestParameters(grantType, clientAssertionType)
      clientAssertion <- jwtValidator
        .validateClientAssertion(clientAssertion, clientUUID)
    } yield clientAssertion

  def verifyClientAssertionSignature(keyWithClient: KeyWithClient, validationResult: AssertionValidationResult)(
    jwtValidator: ClientAssertionValidator
  ): Either[SignatureVerificationFailure, Unit] =
    jwtValidator
      .verifySignature(validationResult, AuthorizationManagementUtils.serializeKey(keyWithClient.key))

  def verifyPlatformState(
    client: Client,
    clientAssertion: ClientAssertion
  ): Either[NonEmptyList[StatesVerificationFailure], Unit] =
    client.kind match {
      case ClientKind.CONSUMER => verifyConsumerClient(client, clientAssertion)
      case ClientKind.API      => Right(())
    }

  private def validateRequestParameters(
    grantType: String,
    assertionType: String
  ): Either[NonEmptyList[ValidationFailure], Unit] =
    (validateGrantType(grantType), validateAssertionType(assertionType)).tupled.as(()).toEither

  private def validateGrantType(grantType: String): ValidatedNel[ValidationFailure, Unit] =
    if (grantType != clientCredentialsGrantType) InvalidGrantType(grantType).invalidNel
    else ().validNel

  private def validateAssertionType(assertionType: String): ValidatedNel[ValidationFailure, Unit] =
    if (assertionType != clientAssertionType) InvalidAssertionType(assertionType).invalidNel
    else ().validNel

  private def verifyConsumerClient(
    client: Client,
    clientAssertion: ClientAssertion
  ): Either[NonEmptyList[StatesVerificationFailure], Unit] =
    for {
      purposeId <- clientAssertion.purposeId
        .fold[StatesValidationResult[UUID]](PurposeIdNotProvided.invalidNel)(_.validNel)
        .toEither
      purpose   <- client.purposes
        .find(_.states.purpose.purposeId == purposeId)
        .fold[StatesValidationResult[Purpose]](PurposeNotFound(client.id, purposeId).invalidNel)(_.validNel)
        .toEither
      _         <- checkConsumerClientValidity(purpose).toEither
    } yield ()

  private def checkConsumerClientValidity(purpose: Purpose): Validated[NonEmptyList[InactivePlatformState], Unit] = {

    def validate(
      state: ClientComponentState,
      error: InactivePlatformState
    ): Validated[NonEmptyList[InactivePlatformState], ClientComponentState] =
      Validated.validNel(state).ensureOr(_ => NonEmptyList.one(error))(_ == ClientComponentState.ACTIVE)

    val validation: Validated[NonEmptyList[
      InactivePlatformState
    ], (ClientComponentState, ClientComponentState, ClientComponentState)] =
      (
        validate(purpose.states.purpose.state, InactivePurpose),
        validate(purpose.states.eservice.state, InactiveEService),
        validate(purpose.states.agreement.state, InactiveAgreement)
      ).tupled

    validation.map(_ => ())
  }
}
