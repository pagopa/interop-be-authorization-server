package it.pagopa.interop.authorizationserver.service.impl

import com.typesafe.scalalogging.{Logger, LoggerTakingImplicit}
import it.pagopa.interop.authorizationmanagement.client.api.TokenGenerationApi
import it.pagopa.interop.authorizationmanagement.client.invoker.{ApiError, ApiRequest}
import it.pagopa.interop.authorizationmanagement.client.model._
import it.pagopa.interop.authorizationserver.error.AuthServerErrors.KeyNotFound
import it.pagopa.interop.authorizationserver.service.{AuthorizationManagementInvoker, AuthorizationManagementService}
import it.pagopa.interop.commons.logging.{CanLogContextFields, ContextFieldsToLog}
import it.pagopa.interop.commons.utils.AkkaUtils.fastGetOpt
import it.pagopa.interop.commons.utils.errors.GenericComponentErrors
import it.pagopa.interop.commons.utils.{CORRELATION_ID_HEADER, IP_ADDRESS}

import java.util.UUID
import scala.concurrent.{ExecutionContext, Future}

class AuthorizationManagementServiceImpl(
  invoker: AuthorizationManagementInvoker,
  tokenGenerationApi: TokenGenerationApi
)(implicit ec: ExecutionContext)
    extends AuthorizationManagementService {

  implicit val logger: LoggerTakingImplicit[ContextFieldsToLog] =
    Logger.takingImplicit[ContextFieldsToLog](this.getClass)

  override def getKeyWithClient(clientId: UUID, kid: String)(implicit
    contexts: Seq[(String, String)]
  ): Future[KeyWithClient] = fastGetOpt(contexts)(CORRELATION_ID_HEADER)
    .fold(Future.failed[KeyWithClient](GenericComponentErrors.MissingHeader(CORRELATION_ID_HEADER))) { correlationId =>
      val ip: Option[String]                 = fastGetOpt(contexts)(IP_ADDRESS)
      val request: ApiRequest[KeyWithClient] =
        tokenGenerationApi.getKeyWithClientByKeyId(xCorrelationId = correlationId, clientId, kid, xForwardedFor = ip)
      invoker
        .invoke(request, "Key Retrieve")
        .recoverWith {
          case err: ApiError[_] if err.code == 404 => Future.failed(KeyNotFound(clientId, kid))
        }
    }

}
