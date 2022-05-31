package it.pagopa.interop.authorizationserver.api.impl

import akka.http.scaladsl.marshalling.ToEntityMarshaller
import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Directives.{complete, onComplete}
import akka.http.scaladsl.server.Route
import cats.data.Validated.{Invalid, Valid}
import cats.data.{NonEmptyList, Validated}
import cats.implicits._
import com.typesafe.scalalogging.{Logger, LoggerTakingImplicit}
import it.pagopa.interop.authorizationmanagement.client.invoker.{ApiError => AuthorizationApiError}
import it.pagopa.interop.authorizationmanagement.client.model.{
  Client,
  ClientComponentState,
  ClientKind,
  ClientStatesChain
}
import it.pagopa.interop.authorizationserver.api.AuthApiService
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.error.AuthServerErrors._
import it.pagopa.interop.authorizationserver.model.TokenType.Bearer
import it.pagopa.interop.authorizationserver.model.{ClientCredentialsResponse, JWTDetailsMessage, Problem}
import it.pagopa.interop.authorizationserver.service.{
  AuthorizationManagementInvoker,
  AuthorizationManagementService,
  QueueService
}
import it.pagopa.interop.commons.jwt.errors.InvalidAccessTokenRequest
import it.pagopa.interop.commons.jwt.model.{ClientAssertionChecker, Token, ValidClientAssertionRequest}
import it.pagopa.interop.commons.jwt.service.{ClientAssertionValidator, InteropTokenGenerator}
import it.pagopa.interop.commons.jwt.{JWTConfiguration, JWTInternalTokenConfig}
import it.pagopa.interop.commons.logging.{CanLogContextFields, ContextFieldsToLog}
import it.pagopa.interop.commons.utils.TypeConversions._
import it.pagopa.interop.commons.utils.errors.ComponentError
import it.pagopa.interop.commons.utils.{BEARER, CORRELATION_ID_HEADER, ORGANIZATION_ID_CLAIM, PURPOSE_ID_CLAIM}

import java.util.UUID
import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success, Try}

final case class AuthApiServiceImpl(
  authorizationManagementService: AuthorizationManagementService,
  jwtValidator: ClientAssertionValidator,
  interopTokenGenerator: InteropTokenGenerator,
  queueService: QueueService
)(implicit ec: ExecutionContext)
    extends AuthApiService {

  val logger: LoggerTakingImplicit[ContextFieldsToLog] = Logger.takingImplicit[ContextFieldsToLog](this.getClass)

  lazy val jwtConfig: JWTInternalTokenConfig = JWTConfiguration.jwtInternalTokenConfig

  override def createToken(
    clientId: Option[String],
    clientAssertion: String,
    clientAssertionType: String,
    grantType: String
  )(implicit
    contexts: Seq[(String, String)],
    toEntityMarshallerClientCredentialsResponse: ToEntityMarshaller[ClientCredentialsResponse],
    toEntityMarshallerProblem: ToEntityMarshaller[Problem]
  ): Route = {
    val getChecker: Try[ClientAssertionChecker] = for {
      clientUUID             <- clientId.traverse(_.toUUID)
      clientAssertionRequest <- ValidClientAssertionRequest
        .from(clientAssertion, clientAssertionType, grantType, clientUUID)
        .recoverWith { case err: InvalidAccessTokenRequest => Failure(InvalidAssertion(err.errors.mkString(","))) }
      checker                <- jwtValidator
        .extractJwtInfo(clientAssertionRequest)
        .recoverWith { case err => Failure(InvalidAssertion(err.getMessage)) }
    } yield checker

    val result: Future[ClientCredentialsResponse] = for {
      checker  <- getChecker.toFuture
      m2mToken <- interopTokenGenerator
        .generateInternalToken(
          subject = jwtConfig.subject,
          audience = jwtConfig.audience.toList,
          tokenIssuer = jwtConfig.issuer,
          secondsDuration = jwtConfig.durationInSeconds
        )

      m2mContexts = contexts.filter(_._1 == CORRELATION_ID_HEADER) :+ (BEARER -> m2mToken.serialized)
      clientUUID                <- checker.subject.toFutureUUID
      publicKey                 <- authorizationManagementService
        .getKey(clientUUID, checker.kid)(m2mContexts)
        .map(k => AuthorizationManagementInvoker.serializeKey(k.key))
        .recoverWith {
          case err: AuthorizationApiError[_] if err.code == 404 => Future.failed(KeyNotFound(err.getMessage))
        }
      _                         <- checker
        .verify(publicKey)
        .toFuture
        .recoverWith(ex => Future.failed(InvalidAssertionSignature(clientUUID, checker.kid, ex.getMessage)))
      purposeId                 <- checker.purposeId.traverse(_.toFutureUUID)
      client                    <- authorizationManagementService.getClient(clientUUID)(m2mContexts)
      (audience, tokenDuration) <- checkClientValidity(client, purposeId)
      customClaims              <- getCustomClaims(client, purposeId)
      token                     <- interopTokenGenerator
        .generate(
          clientAssertion = clientAssertion,
          audience = audience.toList,
          customClaims = customClaims,
          tokenIssuer = ApplicationConfiguration.generatedJwtIssuer,
          validityDurationInSeconds = tokenDuration.toLong,
          isM2M = client.kind == ClientKind.API
        )
      _                         <- sendToQueue(token, client, purposeId, checker.kid)
    } yield ClientCredentialsResponse(access_token = token.serialized, token_type = Bearer, expires_in = tokenDuration)

    onComplete(result) {
      case Success(token)              => createToken200(token)
      case Failure(ex: ComponentError) =>
        logger.error(s"Error while creating a token", ex)
        createToken400(problemOf(StatusCodes.BadRequest, CreateTokenRequestError))
      case Failure(ex)                 =>
        logger.error(s"Error while creating a token for this request", ex)
        complete(StatusCodes.InternalServerError, problemOf(StatusCodes.InternalServerError, CreateTokenRequestError))
    }
  }

  private def checkClientValidity(client: Client, purposeId: Option[UUID]): Future[(Seq[String], Int)] = {
    def checkClientStates(statesChain: ClientStatesChain): Future[Unit] = {

      def validate(
        state: ClientComponentState,
        error: ComponentError
      ): Validated[NonEmptyList[ComponentError], ClientComponentState] =
        Validated.validNel(state).ensureOr(_ => NonEmptyList.one(error))(_ == ClientComponentState.ACTIVE)

      val validation
        : Validated[NonEmptyList[ComponentError], (ClientComponentState, ClientComponentState, ClientComponentState)] =
        (
          validate(statesChain.purpose.state, InactivePurpose(statesChain.purpose.state.toString)),
          validate(statesChain.eservice.state, InactiveEService(statesChain.eservice.state.toString)),
          validate(statesChain.agreement.state, InactiveAgreement(statesChain.agreement.state.toString))
        ).tupled

      validation match {
        case Invalid(e) => Future.failed(InactiveClient(client.id, e.map(_.getMessage).toList))
        case Valid(_)   => Future.successful(())
      }

    }

    client.kind match {
      case ClientKind.CONSUMER =>
        for {
          purposeUUID <- purposeId.toFuture(PurposeIdNotProvided)
          purpose     <- client.purposes
            .find(_.purposeId == purposeUUID)
            .toFuture(PurposeNotFound(client.id, purposeUUID))
          _           <- checkClientStates(purpose.states)
        } yield (purpose.states.eservice.audience, purpose.states.eservice.voucherLifespan)
      case ClientKind.API      =>
        Future.successful(
          (ApplicationConfiguration.generatedM2mJwtAudience.toSeq, ApplicationConfiguration.generatedM2mJwtDuration)
        )
    }
  }

  private def getCustomClaims(client: Client, purposeId: Option[UUID]): Future[Map[String, String]] =
    client.kind match {
      case ClientKind.CONSUMER => purposeId.toFuture(PurposeIdNotProvided).map(p => Map(PURPOSE_ID_CLAIM -> p.toString))
      case ClientKind.API      => Future.successful(Map(ORGANIZATION_ID_CLAIM -> client.consumerId.toString))
    }

  private def sendToQueue(token: Token, client: Client, purposeId: Option[UUID], kid: String)(implicit
    contexts: Seq[(String, String)]
  ): Future[Unit] = {
    val jwtDetails = JWTDetailsMessage(
      jti = token.jti,
      iat = token.iat,
      exp = token.exp,
      nbf = token.nbf,
      organizationId = client.consumerId.toString,
      clientId = client.id.toString,
      purposeId = purposeId.map(_.toString),
      kid = kid
    )

    queueService
      .send(jwtDetails)
      .void
      .recoverWith(ex =>
        Future.successful(
          logger.error(s"Unable to save JWT details to queue. Details: ${jwtDetails.readableString}", ex)
        )
      )
  }

}
