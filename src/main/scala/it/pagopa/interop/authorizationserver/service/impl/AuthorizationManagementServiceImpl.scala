package it.pagopa.interop.authorizationserver.service.impl

import com.typesafe.scalalogging.{Logger, LoggerTakingImplicit}
import it.pagopa.interop.authorizationmanagement.client.api.TokenGenerationApi
import it.pagopa.interop.authorizationmanagement.client.invoker.ApiError
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.authorizationserver.service.{AuthorizationManagementInvoker, AuthorizationManagementService}
import it.pagopa.interop.commons.logging.{CanLogContextFields, ContextFieldsToLog}
import it.pagopa.interop.commons.utils.TypeConversions._
import it.pagopa.interop.commons.utils.errors.GenericComponentErrors.MissingHeader
import it.pagopa.interop.commons.utils.errors.{ComponentError, GenericComponentErrors}
import it.pagopa.interop.commons.utils.{CORRELATION_ID_HEADER, IP_ADDRESS}

import java.util.UUID
import scala.concurrent.{ExecutionContext, Future}

class AuthorizationManagementServiceImpl(
  invoker: AuthorizationManagementInvoker,
  tokenGenerationApi: TokenGenerationApi
)(implicit blockingEc: ExecutionContext)
    extends AuthorizationManagementService {

  implicit val logger: LoggerTakingImplicit[ContextFieldsToLog] =
    Logger.takingImplicit[ContextFieldsToLog](this.getClass)

  def extractHeaders(contexts: Seq[(String, String)]): Either[ComponentError, (String, Option[String])] = {
    val contextsMap = contexts.toMap
    for {
      correlationId <- contextsMap.get(CORRELATION_ID_HEADER).toRight(MissingHeader(CORRELATION_ID_HEADER))
      ip = contextsMap.get(IP_ADDRESS)
    } yield (correlationId, ip)
  }

  override def getKeyWithClient(clientId: UUID, kid: String)(implicit
    contexts: Seq[(String, String)]
  ): Future[KeyWithClient] =
    for {
      (correlationId, ip) <- extractHeaders(contexts).toFuture
      request = tokenGenerationApi.getClientAndKeyByKeyId(
        xCorrelationId = correlationId,
        clientId,
        kid,
        xForwardedFor = ip
      )
      result <- invoker.invoke(request, "Key Retrieve", handleCommonErrors(s"clientKey $kid for client $clientId"))
    } yield result

  private[service] def handleCommonErrors[T](
    resource: String
  ): (ContextFieldsToLog, LoggerTakingImplicit[ContextFieldsToLog], String) => PartialFunction[Throwable, Future[T]] = {
    (context, logger, msg) =>
      {
        case ex @ ApiError(code, message, _, _, _) if code == 404 =>
          logger.error(s"$msg. code > $code - message > $message", ex)(context)
          Future.failed(GenericComponentErrors.ResourceNotFoundError(resource))
        case ex                                                   =>
          logger.error(s"$msg", ex)(context)
          Future.failed(ex)
      }
  }
}
