package it.pagopa.interop.authorizationserver.utils

import it.pagopa.interop.authorizationmanagement.client.model.{Client, ClientKey}
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.model.JWTDetailsMessage
import it.pagopa.interop.authorizationserver.utils.SpecData._
import it.pagopa.interop.commons.jwt.JWTInternalTokenConfig
import it.pagopa.interop.commons.jwt.model.{JWTAlgorithmType, RSA, Token}
import it.pagopa.interop.commons.utils.{ORGANIZATION_ID_CLAIM, PURPOSE_ID_CLAIM}
import org.scalamock.handlers.{CallHandler2, CallHandler3, CallHandler5}
import spray.json.JsonWriter

import java.util.UUID
import scala.concurrent.Future
import scala.util.{Success, Try}

trait SpecHelper { self: BaseSpec =>

  def mockInternalTokenGeneration(
    jwtConfig: JWTInternalTokenConfig
  ): CallHandler5[JWTAlgorithmType, String, List[String], String, Long, Try[Token]] =
    (mockInteropTokenGenerator
      .generateInternalToken(_: JWTAlgorithmType, _: String, _: List[String], _: String, _: Long))
      .expects(RSA, jwtConfig.subject, jwtConfig.audience.toList, jwtConfig.issuer, jwtConfig.durationInSeconds)
      .once()
      .returns(Success(internalToken))

  def mockKeyRetrieve(
    result: ClientKey = clientKey
  ): CallHandler3[UUID, String, Seq[(String, String)], Future[ClientKey]] =
    (mockAuthorizationManagementService
      .getKey(_: UUID, _: String)(_: Seq[(String, String)]))
      .expects(clientId, kid, *)
      .once()
      .returns(Future.successful(result))

  def mockClientRetrieve(result: Client = activeClient): CallHandler2[UUID, Seq[(String, String)], Future[Client]] =
    (mockAuthorizationManagementService
      .getClient(_: UUID)(_: Seq[(String, String)]))
      .expects(clientId, *)
      .once()
      .returns(Future.successful(result))

  def mockConsumerTokenGeneration(): CallHandler5[String, List[String], Map[String, String], String, Long, Try[Token]] =
    (mockInteropTokenGenerator
      .generate(_: String, _: List[String], _: Map[String, String], _: String, _: Long))
      .expects(
        validClientAssertion,
        List(eServiceAudience),
        Map(PURPOSE_ID_CLAIM -> purposeId.toString),
        ApplicationConfiguration.interopIdIssuer,
        eServiceTokenDuration.toLong
      )
      .once()
      .returns(Success(generatedToken))

  def mockApiTokenGeneration(): CallHandler5[String, List[String], Map[String, String], String, Long, Try[Token]] =
    (mockInteropTokenGenerator
      .generate(_: String, _: List[String], _: Map[String, String], _: String, _: Long))
      .expects(
        validClientAssertion,
        List(interopAudience),
        Map(ORGANIZATION_ID_CLAIM -> consumerId.toString),
        ApplicationConfiguration.interopIdIssuer,
        ApplicationConfiguration.interopTokenDuration.toLong
      )
      .once()
      .returns(Success(generatedToken))

  def mockQueueMessagePublication(): CallHandler2[JWTDetailsMessage, JsonWriter[JWTDetailsMessage], Future[String]] =
    (mockQueueService
      .send(_: JWTDetailsMessage)(_: JsonWriter[JWTDetailsMessage]))
      .expects(expectedQueueMessage, *)
      .once()
      .returns(Future.successful("ok"))

}
