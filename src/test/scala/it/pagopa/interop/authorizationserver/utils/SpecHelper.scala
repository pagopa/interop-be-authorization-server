package it.pagopa.interop.authorizationserver.utils

import it.pagopa.interop.authorizationmanagement.client.model.{Client, ClientKey}
import it.pagopa.interop.authorizationserver.common.ApplicationConfiguration
import it.pagopa.interop.authorizationserver.utils.SpecData._
import it.pagopa.interop.commons.jwt.JWTInternalTokenConfig
import it.pagopa.interop.commons.jwt.model.{RSA, Token}
import it.pagopa.interop.commons.utils.PURPOSE_ID_CLAIM
import org.mockito.stubbing.ScalaOngoingStubbing

import scala.concurrent.Future
import scala.util.{Success, Try}

trait SpecHelper { self: BaseSpec =>

  def mockInternalTokenGeneration(jwtConfig: JWTInternalTokenConfig): ScalaOngoingStubbing[Try[Token]] =
    mockInteropTokenGenerator
      .generateInternalToken(
        eqTo(RSA),
        eqTo(jwtConfig.subject),
        eqTo(jwtConfig.audience.toList),
        eqTo(jwtConfig.issuer),
        eqTo(jwtConfig.durationInSeconds)
      )
      .returns(Success(internalToken))

  def mockKeyRetrieve(): ScalaOngoingStubbing[Future[ClientKey]] =
    mockAuthorizationManagementService
      .getKey(eqTo(clientId), eqTo(kid))(*[Seq[(String, String)]])
      .returns(Future.successful(clientKey))

  def mockClientRetrieve(result: Client = activeClient): ScalaOngoingStubbing[Future[Client]] =
    mockAuthorizationManagementService
      .getClient(eqTo(clientId))(*[Seq[(String, String)]])
      .returns(Future.successful(result))

  def mockTokenGeneration(): ScalaOngoingStubbing[Try[Token]] =
    mockInteropTokenGenerator
      .generate(
        clientAssertion = validClientAssertion,
        audience = List(eServiceAudience),
        customClaims = Map(PURPOSE_ID_CLAIM -> purposeId.toString),
        tokenIssuer = ApplicationConfiguration.interopIdIssuer,
        validityDurationInSeconds = eServiceTokenDuration.toLong // TODO This could be an Int
      )
      .returns(Success(generatedToken))

  def mockQueueMessagePublication(): ScalaOngoingStubbing[Future[String]] =
    mockQueueService.send(expectedQueueMessage).returns(Future.successful("ok"))

}
