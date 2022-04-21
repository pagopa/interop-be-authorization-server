package it.pagopa.interop.authorizationserver.service.impl

import it.pagopa.interop.authorizationserver.service.QueueService
import it.pagopa.interop.commons.queue.QueueAccountInfo
import it.pagopa.interop.commons.queue.impl.SQSSimpleWriter
import spray.json.JsonWriter

import scala.concurrent.{ExecutionContext, Future}

final case class QueueServiceImpl(queueAccountInfo: QueueAccountInfo, queueUrl: String)(implicit ec: ExecutionContext)
    extends QueueService {

  val sqsWriter: SQSSimpleWriter = SQSSimpleWriter(queueAccountInfo, queueUrl)

  override def send[T: JsonWriter](message: T): Future[String] = sqsWriter.send(message)
}
