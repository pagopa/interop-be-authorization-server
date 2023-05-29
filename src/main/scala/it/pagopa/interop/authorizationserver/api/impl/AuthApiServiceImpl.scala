package it.pagopa.interop.authorizationserver.api.impl

import akka.http.scaladsl.marshalling.ToEntityMarshaller
import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Directives.{complete, onComplete}
import akka.http.scaladsl.server.Route
import cats.data.NonEmptyList
import cats.implicits._
import com.typesafe.scalalogging.{Logger, LoggerTakingImplicit}
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.authorizationserver.api.AuthApiService
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.error.AuthServerErrors.ClientAssertionValidationWrapper
import it.pagopa.interop.authorizationserver.error.ResponseHandlers._
import it.pagopa.interop.authorizationserver.model.TokenType.Bearer
import it.pagopa.interop.authorizationserver.model.{
  ClientAssertionDetails,
  ClientCredentialsResponse,
  JWTDetailsMessage,
  Problem
}
import it.pagopa.interop.authorizationserver.service.{AuthorizationManagementService, QueueService}
import it.pagopa.interop.clientassertionvalidation.Errors.{PurposeIdNotProvided, PurposeNotFound}
import it.pagopa.interop.clientassertionvalidation.Validation._
import it.pagopa.interop.clientassertionvalidation.{ClientAssertion, ClientAssertionValidator}
import it.pagopa.interop.commons.jwt.model.Token
import it.pagopa.interop.commons.jwt.service.InteropTokenGenerator
import it.pagopa.interop.commons.jwt.{JWTConfiguration, JWTInternalTokenConfig}
import it.pagopa.interop.commons.logging.{CanLogContextFields, ContextFieldsToLog}
import it.pagopa.interop.commons.ratelimiter.RateLimiter
import it.pagopa.interop.commons.ratelimiter.model.{Headers, RateLimitStatus}
import it.pagopa.interop.commons.utils.AkkaUtils.fastGetOpt
import it.pagopa.interop.commons.utils.TypeConversions._
import it.pagopa.interop.commons.utils._

import java.util.UUID
import scala.concurrent.{ExecutionContext, Future}

object TempUtils {

  implicit class EitherValidationOps[A](val either: Either[NonEmptyList[Throwable], A]) extends AnyVal {
    def toFuture(wrappingError: String => Throwable): Future[A] =
      either.fold(
        e => Future.failed(wrappingError(e.map(_.getMessage).toList.mkString(","))),
        a => Future.successful(a)
      )
  }

}

import it.pagopa.interop.authorizationserver.api.impl.TempUtils._

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
    val result: Future[(ClientCredentialsResponse, RateLimitStatus)] = for {
      validation    <- validateClientAssertion(clientId, clientAssertion, clientAssertionType, grantType)(jwtValidator)
        .toFuture(ClientAssertionValidationWrapper)
      keyWithClient <- getTokenGenerationBundle(validation.clientAssertion.sub, validation.clientAssertion.kid)
      _             <- verifyClientAssertionSignature(keyWithClient, validation)(jwtValidator)
        .leftMap(ex => ClientAssertionValidationWrapper(ex.getMessage))
        .toFuture
      rateLimitStatus <- rateLimiter.rateLimiting(keyWithClient.client.consumerId)
      _               <- verifyPlatformState(keyWithClient.client, validation.clientAssertion).toFuture(
        ClientAssertionValidationWrapper
      )
      token           <- generateToken(keyWithClient.client, validation.clientAssertion)
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

  private def generateToken(client: Client, clientAssertion: ClientAssertion)(implicit
    contexts: Seq[(String, String)]
  ): Future[Token] =
    client.kind match {
      case ClientKind.CONSUMER => generateConsumerToken(client, clientAssertion)
      case ClientKind.API      => generateApiToken(client, clientAssertion)
    }

  def getTokenGenerationBundle(clientId: UUID, kid: String)(implicit
    contexts: Seq[(String, String)]
  ): Future[KeyWithClient] =
    authorizationManagementService
      .getKeyWithClient(clientId, kid)(contexts.filter(c => List(CORRELATION_ID_HEADER, IP_ADDRESS).contains(c._1)))

  private def generateConsumerToken(client: Client, clientAssertion: ClientAssertion)(implicit
    context: Seq[(String, String)]
  ): Future[Token] = for {
    purposeId <- clientAssertion.purposeId.toFuture(PurposeIdNotProvided)
    purpose   <- client.purposes
      .find(_.states.purpose.purposeId == purposeId)
      .toFuture(PurposeNotFound(client.id, purposeId))
    customClaims = clientAssertion.digest
      .fold(Map.empty[String, AnyRef])(digest => Map(DIGEST_CLAIM -> digest.toJavaMap))
      .updated(PURPOSE_ID_CLAIM, purposeId.toString)
    token <- interopTokenGenerator
      .generate(
        clientAssertion = clientAssertion.raw,
        audience = purpose.states.eservice.audience.toList,
        customClaims = customClaims,
        tokenIssuer = ApplicationConfiguration.generatedJwtIssuer,
        validityDurationInSeconds = purpose.states.eservice.voucherLifespan.toLong,
        isM2M = false
      )
    _ <- sendToQueue(token, client, purpose, clientAssertion)
  } yield token

  private def generateApiToken(client: Client, clientAssertion: ClientAssertion): Future[Token] =
    interopTokenGenerator
      .generate(
        clientAssertion = clientAssertion.raw,
        audience = ApplicationConfiguration.generatedM2mJwtAudience.toList,
        customClaims = Map(ORGANIZATION_ID_CLAIM -> client.consumerId.toString),
        tokenIssuer = ApplicationConfiguration.generatedJwtIssuer,
        validityDurationInSeconds = ApplicationConfiguration.generatedM2mJwtDuration.toLong,
        isM2M = true
      )

  private def sendToQueue(token: Token, client: Client, purpose: Purpose, clientAssertion: ClientAssertion)(implicit
    contexts: Seq[(String, String)]
  ): Future[Unit] = {
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
        jwtId = clientAssertion.jti,
        issuedAt = clientAssertion.iat,
        algorithm = clientAssertion.alg,
        keyId = clientAssertion.kid,
        issuer = clientAssertion.iss,
        subject = clientAssertion.sub.toString,
        audience = clientAssertion.aud.mkString(","),
        expirationTime = clientAssertion.exp
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
