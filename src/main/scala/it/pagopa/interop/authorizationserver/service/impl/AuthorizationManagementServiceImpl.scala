package it.pagopa.interop.authorizationserver.service.impl

import it.pagopa.interop.authorizationserver.service.{AuthorizationManagementInvoker, AuthorizationManagementService}
import it.pagopa.interop.authorizationmanagement.client.api.{ClientApi, KeyApi}
import it.pagopa.interop.authorizationmanagement.client.invoker.{ApiError, BearerToken}
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.commons.utils.errors.GenericComponentErrors
import it.pagopa.interop.commons.utils.extractHeaders
import it.pagopa.interop.commons.utils.TypeConversions._
import com.typesafe.scalalogging.{Logger, LoggerTakingImplicit}
import it.pagopa.interop.commons.logging.{CanLogContextFields, ContextFieldsToLog}

import java.util.UUID
import scala.concurrent.{ExecutionContext, Future}

class AuthorizationManagementServiceImpl(invoker: AuthorizationManagementInvoker, keyApi: KeyApi, clientApi: ClientApi)(
  implicit ec: ExecutionContext
) extends AuthorizationManagementService {

  implicit val logger: LoggerTakingImplicit[ContextFieldsToLog] =
    Logger.takingImplicit[ContextFieldsToLog](this.getClass)

  override def getKey(clientId: UUID, kid: String)(implicit contexts: Seq[(String, String)]): Future[ClientKey] =
    for {
      (bearerToken, correlationId, ip) <- extractHeaders(contexts).toFuture
      request = keyApi.getClientKeyById(xCorrelationId = correlationId, clientId, kid, xForwardedFor = ip)(
        BearerToken(bearerToken)
      )
      result <- invoker.invoke(request, "Key Retrieve", handleCommonErrors(s"clientKey $kid for client $clientId"))
    } yield result

  override def getClient(clientId: UUID)(implicit contexts: Seq[(String, String)]): Future[Client] =
    for {
      (bearerToken, correlationId, ip) <- extractHeaders(contexts).toFuture
      request = clientApi.getClient(xCorrelationId = correlationId, clientId, xForwardedFor = ip)(
        BearerToken(bearerToken)
      )
      result <- invoker.invoke(request, "Client retrieval", handleCommonErrors(s"client $clientId"))
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
