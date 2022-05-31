package it.pagopa.interop.authorizationserver.utils

import it.pagopa.interop.authorizationmanagement.client.model.{Client, ClientKey}
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.model.JWTDetailsMessage
import it.pagopa.interop.authorizationserver.utils.SpecData._
import it.pagopa.interop.commons.jwt.JWTInternalTokenConfig
import it.pagopa.interop.commons.utils.{ORGANIZATION_ID_CLAIM, PURPOSE_ID_CLAIM}
import spray.json.JsonWriter

import java.util.UUID
import scala.concurrent.Future

trait SpecHelper { self: BaseSpec =>

  def mockInternalTokenGeneration(jwtConfig: JWTInternalTokenConfig) =
    (mockInteropTokenGenerator
      .generateInternalToken(_: String, _: List[String], _: String, _: Long))
      .expects(jwtConfig.subject, jwtConfig.audience.toList, jwtConfig.issuer, jwtConfig.durationInSeconds)
      .once()
      .returns(Future.successful(internalToken))

  def mockKeyRetrieve(result: ClientKey = clientKey) =
    (mockAuthorizationManagementService
      .getKey(_: UUID, _: String)(_: Seq[(String, String)]))
      .expects(clientId, kid, *)
      .once()
      .returns(Future.successful(result))

  def mockClientRetrieve(result: Client = activeClient) =
    (mockAuthorizationManagementService
      .getClient(_: UUID)(_: Seq[(String, String)]))
      .expects(clientId, *)
      .once()
      .returns(Future.successful(result))

  def mockConsumerTokenGeneration() =
    (mockInteropTokenGenerator
      .generate(_: String, _: List[String], _: Map[String, String], _: String, _: Long, _: Boolean))
      .expects(
        validClientAssertion,
        List(eServiceAudience),
        Map(PURPOSE_ID_CLAIM -> purposeId.toString),
        ApplicationConfiguration.generatedJwtIssuer,
        eServiceTokenDuration.toLong,
        false
      )
      .once()
      .returns(Future.successful(generatedToken))

  def mockApiTokenGeneration() =
    (mockInteropTokenGenerator
      .generate(_: String, _: List[String], _: Map[String, String], _: String, _: Long, _: Boolean))
      .expects(
        validClientAssertion,
        ApplicationConfiguration.generatedM2mJwtAudience.toList,
        Map(ORGANIZATION_ID_CLAIM -> consumerId.toString),
        ApplicationConfiguration.generatedJwtIssuer,
        ApplicationConfiguration.generatedM2mJwtDuration.toLong,
        true
      )
      .once()
      .returns(Future.successful(generatedToken))

  def mockQueueMessagePublication() =
    (mockQueueService
      .send(_: JWTDetailsMessage)(_: JsonWriter[JWTDetailsMessage]))
      .expects(expectedQueueMessage, *)
      .once()
      .returns(Future.successful("ok"))

}
