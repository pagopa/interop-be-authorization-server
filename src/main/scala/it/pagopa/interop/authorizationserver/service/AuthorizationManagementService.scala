package it.pagopa.interop.authorizationserver.service

import it.pagopa.interop.authorizationmanagement.client.model._

import java.util.UUID
import scala.concurrent.Future

trait AuthorizationManagementService {

  def getKey(clientId: UUID, kid: String)(implicit contexts: Seq[(String, String)]): Future[ClientKey]
  def getClient(clientId: UUID)(implicit contexts: Seq[(String, String)]): Future[Client]

}
