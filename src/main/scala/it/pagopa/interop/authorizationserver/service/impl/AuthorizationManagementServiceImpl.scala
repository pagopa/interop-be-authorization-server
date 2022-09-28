package it.pagopa.interop.authorizationserver.service.impl

import com.typesafe.scalalogging.{Logger, LoggerTakingImplicit}
import it.pagopa.interop.authorizationmanagement.client.api.TokenGenerationApi
import it.pagopa.interop.authorizationmanagement.client.invoker.ApiError
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.authorizationserver.service.{AuthorizationManagementInvoker, AuthorizationManagementService}
import it.pagopa.interop.commons.logging.{CanLogContextFields, ContextFieldsToLog}
import it.pagopa.interop.commons.utils.errors.GenericComponentErrors
import it.pagopa.interop.commons.utils.withHeaders

import java.util.UUID
import scala.concurrent.Future

class AuthorizationManagementServiceImpl(
  invoker: AuthorizationManagementInvoker,
  tokenGenerationApi: TokenGenerationApi
) extends AuthorizationManagementService {

  implicit val logger: LoggerTakingImplicit[ContextFieldsToLog] =
    Logger.takingImplicit[ContextFieldsToLog](this.getClass)

  override def getKeyWithClient(clientId: UUID, kid: String)(implicit
    contexts: Seq[(String, String)]
  ): Future[KeyWithClient] =
    withHeaders { (_, correlationId, ip) =>
      val request =
        tokenGenerationApi.getKeyWithClientByKeyId(xCorrelationId = correlationId, clientId, kid, xForwardedFor = ip)
      invoker.invoke(request, "Key Retrieve", handleCommonErrors(s"clientKey $kid for client $clientId"))
    }

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
