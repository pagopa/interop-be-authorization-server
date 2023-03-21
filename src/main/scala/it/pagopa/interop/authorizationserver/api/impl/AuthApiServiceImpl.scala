package it.pagopa.interop.authorizationserver.api.impl

import akka.http.scaladsl.marshalling.ToEntityMarshaller
import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Directives.{complete, onComplete}
import akka.http.scaladsl.server.Route
import cats.data.Validated.{Invalid, Valid}
import cats.data.{NonEmptyList, Validated}
import cats.implicits._
import com.typesafe.scalalogging.{Logger, LoggerTakingImplicit}
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.authorizationserver.api.AuthApiService
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.error.AuthServerErrors._
import it.pagopa.interop.authorizationserver.error.ResponseHandlers._
import it.pagopa.interop.authorizationserver.model.TokenType.Bearer
import it.pagopa.interop.authorizationserver.model.{
  ClientAssertionDetails,
  ClientCredentialsResponse,
  JWTDetailsMessage,
  Problem
}
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
import it.pagopa.interop.commons.ratelimiter.RateLimiter
import it.pagopa.interop.commons.ratelimiter.model.{Headers, RateLimitStatus}
import it.pagopa.interop.commons.utils.AkkaUtils.fastGetOpt
import it.pagopa.interop.commons.utils.TypeConversions._
import it.pagopa.interop.commons.utils.errors.ComponentError
import it.pagopa.interop.commons.utils.{CORRELATION_ID_HEADER, IP_ADDRESS, ORGANIZATION_ID_CLAIM, PURPOSE_ID_CLAIM}

import java.util.UUID
import scala.concurrent.{ExecutionContext, Future}
import scala.jdk.CollectionConverters._
import scala.util.Try

final case class AuthApiServiceImpl(
  authorizationManagementService: AuthorizationManagementService,
  jwtValidator: ClientAssertionValidator,
  interopTokenGenerator: InteropTokenGenerator,
  queueService: QueueService,
  rateLimiter: RateLimiter
)(implicit blockingEc: ExecutionContext)
    extends AuthApiService {

  implicit val logger: LoggerTakingImplicit[ContextFieldsToLog] =
    Logger.takingImplicit[ContextFieldsToLog](this.getClass)

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
      clientUUID             <- clientId.traverse(id => id.toUUID.leftMap(_ => InvalidClientIdFormat(id)))
      clientAssertionRequest <- ValidClientAssertionRequest
        .from(clientAssertion, clientAssertionType, grantType, clientUUID)
        .adaptError { case err: InvalidAccessTokenRequest => InvalidAssertion(err.errors.mkString(",")) }
      checker                <- jwtValidator
        .extractJwtInfo(clientAssertionRequest)
        .adaptError(err => InvalidAssertion(err.getMessage))
    } yield checker

    val result: Future[(ClientCredentialsResponse, RateLimitStatus)] = for {
      checker         <- getChecker.toFuture
      keyWithClient   <- getTokenGenerationBundle(checker.subject, checker.kid)
      _               <- verifyClientAssertion(keyWithClient, checker)
      rateLimitStatus <- rateLimiter.rateLimiting(keyWithClient.client.consumerId)
      token           <- generateToken(keyWithClient.client, checker, clientAssertion)
      _ = logger.info(
        s"Token with jti ${token.jti} generated for client ${keyWithClient.client.id} of type ${keyWithClient.client.kind.toString}"
      )
    } yield (
      ClientCredentialsResponse(access_token = token.serialized, token_type = Bearer, expires_in = token.expIn.toInt),
      rateLimitStatus
    )

    onComplete(result) {
      createTokenResponse[(ClientCredentialsResponse, RateLimitStatus)]("Token Generation") {
        case (token, rateLimitStatus) => complete(StatusCodes.OK, Headers.headersFromStatus(rateLimitStatus), token)
      }
    }
  }

  private def generateToken(client: Client, checker: ClientAssertionChecker, clientAssertion: String)(implicit
    contexts: Seq[(String, String)]
  ): Future[Token] =
    client.kind match {
      case ClientKind.CONSUMER => generateConsumerToken(client, checker, clientAssertion)
      case ClientKind.API      => generateApiToken(client, clientAssertion)
    }

  def getTokenGenerationBundle(clientId: UUID, kid: String)(implicit
    contexts: Seq[(String, String)]
  ): Future[KeyWithClient] =
    authorizationManagementService
      .getKeyWithClient(clientId, kid)(contexts.filter(c => List(CORRELATION_ID_HEADER, IP_ADDRESS).contains(c._1)))

  private def generateConsumerToken(client: Client, checker: ClientAssertionChecker, clientAssertion: String)(implicit
    context: Seq[(String, String)]
  ): Future[Token] = for {
    purposeId                 <- checker.purposeId.toFuture(PurposeIdNotProvided)
    purpose                   <- client.purposes
      .find(_.states.purpose.purposeId == purposeId)
      .toFuture(PurposeNotFound(client.id, purposeId))
    (audience, tokenDuration) <- checkConsumerClientValidity(client, purpose)
    customClaims = Map(PURPOSE_ID_CLAIM -> purposeId.toString)
    token <- interopTokenGenerator
      .generate(
        clientAssertion = clientAssertion,
        audience = audience.toList,
        customClaims = customClaims,
        tokenIssuer = ApplicationConfiguration.generatedJwtIssuer,
        validityDurationInSeconds = tokenDuration.toLong,
        isM2M = false
      )
    _     <- sendToQueue(token, client, purpose, checker)
  } yield token

  private def generateApiToken(client: Client, clientAssertion: String): Future[Token] =
    interopTokenGenerator
      .generate(
        clientAssertion = clientAssertion,
        audience = ApplicationConfiguration.generatedM2mJwtAudience.toList,
        customClaims = Map(ORGANIZATION_ID_CLAIM -> client.consumerId.toString),
        tokenIssuer = ApplicationConfiguration.generatedJwtIssuer,
        validityDurationInSeconds = ApplicationConfiguration.generatedM2mJwtDuration.toLong,
        isM2M = true
      )

  private def checkConsumerClientValidity(client: Client, purpose: Purpose): Future[(Seq[String], Int)] = {
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

    checkClientStates(purpose.states).as((purpose.states.eservice.audience, purpose.states.eservice.voucherLifespan))
  }

  private def verifyClientAssertion(keyWithClient: KeyWithClient, checker: ClientAssertionChecker): Future[Unit] =
    checker
      .verify(AuthorizationManagementInvoker.serializeKey(keyWithClient.key))
      .toFuture
      .recoverWith(ex => Future.failed(InvalidAssertionSignature(keyWithClient.client.id, checker.kid, ex.getMessage)))

  private def sendToQueue(
    token: Token,
    client: Client,
    purpose: Purpose,
    clientAssertionChecker: ClientAssertionChecker
  )(implicit contexts: Seq[(String, String)]): Future[Unit] = {
    val jwtDetails = JWTDetailsMessage(
      jwtId = token.jti,
      correlationId = fastGetOpt(contexts)(CORRELATION_ID_HEADER),
      issuedAt = token.iat * 1000,
      clientId = client.id.toString,
      organizationId = client.consumerId.toString,
      agreementId = purpose.states.agreement.agreementId.toString,
      eserviceId = purpose.states.eservice.eserviceId.toString,
      descriptorId = purpose.states.eservice.descriptorId.toString,
      purposeId = purpose.states.purpose.purposeId.toString,
      purposeVersionId = purpose.states.purpose.versionId.toString,
      algorithm = token.alg,
      keyId = token.kid,
      audience = token.aud.mkString(","),
      subject = token.sub,
      notBefore = token.nbf * 1000,
      expirationTime = token.exp * 1000,
      issuer = token.iss,
      clientAssertion = ClientAssertionDetails(
        jwtId = clientAssertionChecker.jwt.getJWTClaimsSet.getJWTID,
        issuedAt = clientAssertionChecker.jwt.getJWTClaimsSet.getIssueTime.getTime,
        algorithm = clientAssertionChecker.jwt.getHeader.getAlgorithm.getName,
        keyId = clientAssertionChecker.kid,
        issuer = clientAssertionChecker.jwt.getJWTClaimsSet.getIssuer,
        subject = clientAssertionChecker.subject.toString,
        audience = clientAssertionChecker.jwt.getJWTClaimsSet.getAudience.asScala.mkString(","),
        expirationTime = clientAssertionChecker.jwt.getJWTClaimsSet.getExpirationTime.getTime
      )
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
