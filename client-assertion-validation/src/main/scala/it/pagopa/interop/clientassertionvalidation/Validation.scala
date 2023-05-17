package it.pagopa.interop.clientassertionvalidation

import cats.data.Validated.{Invalid, Valid}
import cats.data.{NonEmptyList, Validated}
import cats.implicits._
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.commons.jwt.errors.InvalidAccessTokenRequest
import it.pagopa.interop.commons.jwt.model.{ClientAssertionChecker, ValidClientAssertionRequest}
import it.pagopa.interop.commons.jwt.service.ClientAssertionValidator
import it.pagopa.interop.commons.utils.TypeConversions._
import it.pagopa.interop.commons.utils.errors.ComponentError

object Validation {

  def validateClientAssertion(
    clientId: Option[String],
    clientAssertion: String,
    clientAssertionType: String,
    grantType: String
  )(jwtValidator: ClientAssertionValidator): Either[ComponentError, ClientAssertionChecker] = {
    for {
      clientUUID             <- clientId.traverse(id => id.toUUID.toEither.leftMap(_ => InvalidClientIdFormat(id)))
      clientAssertionRequest <- ValidClientAssertionRequest
        .from(clientAssertion, clientAssertionType, grantType, clientUUID)
        .toEither
        .leftMap {
          case err: InvalidAccessTokenRequest => InvalidAssertion(err.errors.mkString(","))
          case err                            => InvalidAssertion(err.getMessage)
        }
      checker                <- jwtValidator
        .extractJwtInfo(clientAssertionRequest)
        .toEither
        .leftMap(err => InvalidAssertion(err.getMessage))
    } yield checker
  }

  def verifyClientAssertionSignature(
    keyWithClient: KeyWithClient,
    checker: ClientAssertionChecker
  ): Either[ComponentError, Unit] =
    checker
      .verify(AuthorizationManagementUtils.serializeKey(keyWithClient.key))
      .toEither
      .leftMap(ex => InvalidAssertionSignature(keyWithClient.client.id, checker.kid, ex.getMessage))

  def verifyPlatformState(client: Client, checker: ClientAssertionChecker): Either[ComponentError, Unit] =
    client.kind match {
      case ClientKind.CONSUMER => verifyConsumerClient(client, checker)
      case ClientKind.API      => Right(())
    }

  private def verifyConsumerClient(client: Client, checker: ClientAssertionChecker): Either[ComponentError, Unit] =
    for {
      purposeId <- checker.purposeId.toRight(PurposeIdNotProvided)
      purpose   <- client.purposes
        .find(_.states.purpose.purposeId == purposeId)
        .toRight(PurposeNotFound(client.id, purposeId))
      _         <- checkConsumerClientValidity(client, purpose)
    } yield ()

  private def checkConsumerClientValidity(client: Client, purpose: Purpose): Either[ComponentError, Unit] = {

    def validate(
      state: ClientComponentState,
      error: ComponentError
    ): Validated[NonEmptyList[ComponentError], ClientComponentState] =
      Validated.validNel(state).ensureOr(_ => NonEmptyList.one(error))(_ == ClientComponentState.ACTIVE)

    val validation
      : Validated[NonEmptyList[ComponentError], (ClientComponentState, ClientComponentState, ClientComponentState)] =
      (
        validate(purpose.states.purpose.state, InactivePurpose(purpose.states.purpose.state.toString)),
        validate(purpose.states.eservice.state, InactiveEService(purpose.states.eservice.state.toString)),
        validate(purpose.states.agreement.state, InactiveAgreement(purpose.states.agreement.state.toString))
      ).tupled

    validation match {
      case Invalid(e) => Left(InactivePlatformState(client.id, e.toList: _*))
      case Valid(_)   => Right(())
    }
  }
}
