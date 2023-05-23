package it.pagopa.interop.clientassertionvalidation

import cats.data.{NonEmptyList, Validated, ValidatedNel}
import cats.syntax.all._
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.commons.utils.TypeConversions._

import java.util.UUID

object Validation {

  type ValidationResult[A] = ValidatedNel[ClientAssertionValidationError, A]

  private final val clientAssertionType: String        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  private final val clientCredentialsGrantType: String = "client_credentials"

  def validateClientAssertion(
    clientId: Option[String],
    clientAssertion: String,
    clientAssertionType: String,
    grantType: String
  )(
    jwtValidator: ClientAssertionValidator
  ): Either[NonEmptyList[ClientAssertionValidationError], AssertionValidationResult] = {
    for {
      clientUUID      <- clientId.traverse(id =>
        id.toUUID.toEither.leftMap(_ => NonEmptyList(InvalidClientIdFormat(id), Nil))
      )
      _               <- validateRequestParameters(grantType, clientAssertionType)
      clientAssertion <- jwtValidator
        .validateClientAssertion(clientAssertion, clientUUID)
//        .leftMap(err => InvalidAssertion(err.getMessage))
    } yield clientAssertion
  }

  def verifyClientAssertionSignature(keyWithClient: KeyWithClient, clientAssertion: ClientAssertion)(
    jwtValidator: ClientAssertionValidator
  ): Either[ClientAssertionValidationError, Unit] =
    jwtValidator
      .verifySignature(clientAssertion.raw, AuthorizationManagementUtils.serializeKey(keyWithClient.key))
//      .leftMap(ex => InvalidAssertionSignature(keyWithClient.client.id, keyWithClient.key.kid, ex.getMessage))

  def verifyPlatformState(
    client: Client,
    clientAssertion: ClientAssertion
  ): Either[NonEmptyList[ClientAssertionValidationError], Unit] =
    client.kind match {
      case ClientKind.CONSUMER => verifyConsumerClient(client, clientAssertion)
      case ClientKind.API      => Right(())
    }

  def validateRequestParameters(
    grantType: String,
    assertionType: String
  ): Either[NonEmptyList[ClientAssertionValidationError], Unit] =
    (validateGrantType(grantType), validateAssertionType(assertionType)).tupled.as(()).toEither

  def validateGrantType(grantType: String): ValidatedNel[ClientAssertionValidationError, Unit] =
    if (grantType != clientCredentialsGrantType) InvalidGrantType(grantType).invalidNel
    else ().validNel

  def validateAssertionType(assertionType: String): ValidatedNel[ClientAssertionValidationError, Unit] =
    if (assertionType != clientAssertionType) InvalidAssertionType(assertionType).invalidNel
    else ().validNel

  private def verifyConsumerClient(
    client: Client,
    clientAssertion: ClientAssertion
  ): Either[NonEmptyList[ClientAssertionValidationError], Unit] =
    for {
      purposeId <- clientAssertion.purposeId
        .fold[ValidationResult[UUID]](PurposeIdNotProvided.invalidNel)(_.validNel)
        .toEither
      purpose   <- client.purposes
        .find(_.states.purpose.purposeId == purposeId)
        .fold[ValidationResult[Purpose]](PurposeNotFound(client.id, purposeId).invalidNel)(_.validNel)
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
        validate(purpose.states.purpose.state, InactivePurpose(purpose.states.purpose.state.toString)),
        validate(purpose.states.eservice.state, InactiveEService(purpose.states.eservice.state.toString)),
        validate(purpose.states.agreement.state, InactiveAgreement(purpose.states.agreement.state.toString))
      ).tupled

    validation.map(_ => ())
  }
}
