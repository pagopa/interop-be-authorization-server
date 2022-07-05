package it.pagopa.interop.authorizationserver.service.impl

import it.pagopa.interop.authorizationserver.service.QueueService
import it.pagopa.interop.commons.queue.impl.SQSHandler
import spray.json.JsonWriter

import scala.concurrent.{ExecutionContextExecutor, Future}

final case class QueueServiceImpl(queueUrl: String)(implicit blockingEc: ExecutionContextExecutor)
    extends QueueService {

  val sqsHandler: SQSHandler = SQSHandler(queueUrl)(blockingEc)

  override def send[T: JsonWriter](message: T): Future[String] = sqsHandler.send(message)
}
