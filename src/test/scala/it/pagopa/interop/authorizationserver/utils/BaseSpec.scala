package it.pagopa.interop.authorizationserver.utils

import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import akka.http.scaladsl.unmarshalling.FromEntityUnmarshaller
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import it.pagopa.interop.authorizationserver.api.AuthApiService
import it.pagopa.interop.authorizationserver.api.impl.{AuthApiServiceImpl, _}
import it.pagopa.interop.authorizationserver.model.ClientCredentialsResponse
import it.pagopa.interop.authorizationserver.service.{AuthorizationManagementService, QueueService}
import it.pagopa.interop.commons.jwt.{KID, PublicKeysHolder, SerializedKey}
import it.pagopa.interop.commons.jwt.service.impl.{DefaultClientAssertionValidator, getClaimsVerifier}
import it.pagopa.interop.commons.jwt.service.{ClientAssertionValidator, InteropTokenGenerator}
import org.mockito.scalatest.IdiomaticMockito
import org.scalatest.wordspec.AnyWordSpecLike
import spray.json.DefaultJsonProtocol

import scala.concurrent.ExecutionContext

trait BaseSpec extends AnyWordSpecLike with SprayJsonSupport with DefaultJsonProtocol with IdiomaticMockito {

  def clientAssertionValidator(interopAudience: String): ClientAssertionValidator = new DefaultClientAssertionValidator
    with PublicKeysHolder {
    var publicKeyset: Map[KID, SerializedKey]                                        = Map.empty
    override protected val claimsVerifier: DefaultJWTClaimsVerifier[SecurityContext] =
      getClaimsVerifier(audience = Set(interopAudience))
  }

  val mockInteropTokenGenerator: InteropTokenGenerator                   = mock[InteropTokenGenerator]
  val mockAuthorizationManagementService: AuthorizationManagementService = mock[AuthorizationManagementService]
  val mockQueueService: QueueService                                     = mock[QueueService]

  def service(implicit ec: ExecutionContext): AuthApiService = customService()

  def customService(interopAudience: String = SpecData.interopAudience)(implicit ec: ExecutionContext): AuthApiService =
    AuthApiServiceImpl(
      authorizationManagementService = mockAuthorizationManagementService,
      jwtValidator = clientAssertionValidator(interopAudience),
      interopTokenGenerator = mockInteropTokenGenerator,
      queueService = mockQueueService
    )

  implicit def fromResponseUnmarshallerPurpose: FromEntityUnmarshaller[ClientCredentialsResponse] =
    sprayJsonUnmarshaller[ClientCredentialsResponse]

}
