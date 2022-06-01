package it.pagopa.interop.authorizationserver.service.impl

import it.pagopa.interop.authorizationserver.service.QueueService
import it.pagopa.interop.commons.queue.impl.SQSSimpleHandler
import spray.json.JsonWriter

import scala.concurrent.{ExecutionContext, Future}

final case class QueueServiceImpl(queueUrl: String)(implicit ec: ExecutionContext) extends QueueService {

  val sqsHandler: SQSSimpleHandler = SQSSimpleHandler(queueUrl)

  override def send[T: JsonWriter](message: T): Future[String] = sqsHandler.send(message)
}
