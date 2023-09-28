package it.pagopa.interop.authorizationserver.utils

import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import akka.http.scaladsl.unmarshalling.FromEntityUnmarshaller
import it.pagopa.interop.authorizationserver.api.AuthApiService
import it.pagopa.interop.authorizationserver.api.impl.{AuthApiServiceImpl, _}
import it.pagopa.interop.authorizationserver.model.ClientCredentialsResponse
import it.pagopa.interop.authorizationserver.service.{AuthorizationManagementService, QueueService}
import it.pagopa.interop.clientassertionvalidation.SpecData.clientAssertionAudience
import it.pagopa.interop.clientassertionvalidation.{ClientAssertionValidator, NimbusClientAssertionValidator}
import it.pagopa.interop.commons.files.service.FileManager
import it.pagopa.interop.commons.jwt.service.InteropTokenGenerator
import it.pagopa.interop.commons.ratelimiter.RateLimiter
import it.pagopa.interop.commons.utils.service.OffsetDateTimeSupplier
import org.scalamock.scalatest.MockFactory
import org.scalatest.wordspec.AnyWordSpecLike
import spray.json.DefaultJsonProtocol

import scala.concurrent.{ExecutionContext, Future}

trait BaseSpec extends AnyWordSpecLike with SprayJsonSupport with DefaultJsonProtocol with MockFactory {

  def clientAssertionValidator(clientAssertionAudience: String): ClientAssertionValidator =
    new NimbusClientAssertionValidator(Set(clientAssertionAudience))

  val mockInteropTokenGenerator: InteropTokenGenerator                   = mock[InteropTokenGenerator]
  val mockAuthorizationManagementService: AuthorizationManagementService = mock[AuthorizationManagementService]
  val mockQueueService: QueueService                                     = mock[QueueService]
  val mockRateLimiter: RateLimiter                                       = mock[RateLimiter]
  val mockDateTimeSupplier: OffsetDateTimeSupplier                       = mock[OffsetDateTimeSupplier]
  val mockFileManager: FileManager                                       = mock[FileManager]

  def mockFileManagerStore(storageFilePath: String) = (
    mockFileManager.storeBytes(_: String, _: String, _: String)(_: Array[Byte])
  ).expects(*, *, *, *).once().returns(Future.successful(storageFilePath))

  def service(implicit ec: ExecutionContext): AuthApiService = customService()

  def customService(
    clientAssertionAudience: String = clientAssertionAudience
  )(implicit ec: ExecutionContext): AuthApiService =
    AuthApiServiceImpl(
      authorizationManagementService = mockAuthorizationManagementService,
      jwtValidator = clientAssertionValidator(clientAssertionAudience),
      interopTokenGenerator = mockInteropTokenGenerator,
      queueService = mockQueueService,
      rateLimiter = mockRateLimiter,
      dateTimeSupplier = mockDateTimeSupplier,
      fileManager = mockFileManager
    )

  implicit def fromResponseUnmarshallerPurpose: FromEntityUnmarshaller[ClientCredentialsResponse] =
    sprayJsonUnmarshaller[ClientCredentialsResponse]

}
