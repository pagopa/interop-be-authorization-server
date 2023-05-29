package it.pagopa.interop.authorizationserver.error

import akka.http.scaladsl.server.{Route, StandardRoute}
import com.typesafe.scalalogging.LoggerTakingImplicit
import it.pagopa.interop.authorizationserver.error.AuthServerErrors._
import it.pagopa.interop.commons.logging.ContextFieldsToLog
import it.pagopa.interop.commons.ratelimiter
import it.pagopa.interop.commons.ratelimiter.model.Headers
import it.pagopa.interop.commons.utils.errors.GenericComponentErrors.TooManyRequests
import it.pagopa.interop.commons.utils.errors.{AkkaResponses, ComponentError, ServiceCode}

import scala.util.{Failure, Success, Try}

object ResponseHandlers extends AkkaResponses {

  implicit val serviceCode: ServiceCode = ServiceCode("015")

  def createTokenResponse[T](logMessage: String)(
    success: T => Route
  )(result: Try[T])(implicit contexts: Seq[(String, String)], logger: LoggerTakingImplicit[ContextFieldsToLog]): Route =
    result match {
      case Success(s)                                            => success(s)
      case Failure(ex: KeyNotFound)                              => genericBadRequest(ex, logMessage)
      case Failure(ex: ClientAssertionValidationWrapper)         => genericBadRequest(ex, logMessage)
      case Failure(ex: ratelimiter.error.Errors.TooManyRequests) =>
        tooManyRequests(
          TooManyRequests,
          s"Requests limit exceeded for organization ${ex.tenantId}",
          Headers.headersFromStatus(ex.status)
        )
      case Failure(ex)                                           => internalServerError(ex, logMessage)
    }

  private[this] def genericBadRequest(error: ComponentError, logMessage: String)(implicit
    contexts: Seq[(String, String)],
    logger: LoggerTakingImplicit[ContextFieldsToLog]
  ): StandardRoute = {
    logger.warn(s"Root cause for $logMessage", error)
    badRequest(CreateTokenRequestError, logMessage)
  }
}
