package it.pagopa.interop.authorizationserver.error

import akka.http.scaladsl.server.StandardRoute
import com.typesafe.scalalogging.LoggerTakingImplicit
import it.pagopa.interop.authorizationserver.error.AuthServerErrors._
import it.pagopa.interop.commons.logging.ContextFieldsToLog
import it.pagopa.interop.commons.ratelimiter
import it.pagopa.interop.commons.ratelimiter.model.Headers
import it.pagopa.interop.commons.utils.errors.GenericComponentErrors.TooManyRequests
import it.pagopa.interop.commons.utils.errors.{AkkaResponses, ServiceCode}

import scala.util.{Failure, Try}

object Handlers extends AkkaResponses {

  implicit val serviceCode: ServiceCode = ServiceCode("015")

  def handleTokenGenerationError(logMessage: String)(implicit
    contexts: Seq[(String, String)],
    logger: LoggerTakingImplicit[ContextFieldsToLog]
  ): PartialFunction[Try[_], StandardRoute] = {
    case Failure(ex: PurposeNotFound)                          => badRequest(ex, logMessage)
    case Failure(ex: InactiveClient)                           => badRequest(ex, logMessage)
    case Failure(ex: InactivePurpose)                          => badRequest(ex, logMessage)
    case Failure(ex: InactiveEService)                         => badRequest(ex, logMessage)
    case Failure(ex: InactiveAgreement)                        => badRequest(ex, logMessage)
    case Failure(ex: PurposeIdNotProvided.type)                => badRequest(ex, logMessage)
    case Failure(ex: InvalidAssertion)                         => badRequest(ex, logMessage)
    case Failure(ex: KeyNotFound)                              => badRequest(ex, logMessage)
    case Failure(ex: InvalidAssertionSignature)                => badRequest(ex, logMessage)
    case Failure(ex: ratelimiter.error.Errors.TooManyRequests) =>
      tooManyRequests(TooManyRequests, logMessage, Headers.headersFromStatus(ex.status))
    case Failure(ex)                                           => internalServerError(ex, logMessage)
  }
}
