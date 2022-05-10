package it.pagopa.interop.authorizationserver.service.impl

import it.pagopa.interop.authorizationserver.service.QueueService
import it.pagopa.interop.commons.queue.QueueAccountInfo
import it.pagopa.interop.commons.queue.impl.SQSSimpleHandler
import spray.json.JsonWriter

import scala.concurrent.{ExecutionContext, Future}

final case class QueueServiceImpl(queueAccountInfo: QueueAccountInfo, queueUrl: String)(implicit ec: ExecutionContext)
    extends QueueService {

  val sqsHandler: SQSSimpleHandler = SQSSimpleHandler(queueAccountInfo, queueUrl)

  override def send[T: JsonWriter](message: T): Future[String] = sqsHandler.send(message)
}
