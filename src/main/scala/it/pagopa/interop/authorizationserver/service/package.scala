package it.pagopa.interop.authorizationserver

import akka.actor.ActorSystem
import it.pagopa.interop._
import it.pagopa.interop.authorizationmanagement.client.model.Key
import it.pagopa.interop.authorizationmanagement.client.invoker.Serializers
import org.json4s.jackson.Serialization
import org.json4s.{DefaultFormats, Formats}

package object service {
  type AuthorizationManagementInvoker = authorizationmanagement.client.invoker.ApiInvoker

  object AuthorizationManagementInvoker {
    def apply()(implicit actorSystem: ActorSystem): AuthorizationManagementInvoker = {
      authorizationmanagement.client.invoker.ApiInvoker(authorizationmanagement.client.api.EnumsSerializers.all)
    }

    private def serializationFormats: Formats =
      DefaultFormats ++ Serializers.all ++ authorizationmanagement.client.api.EnumsSerializers.all
    def serializeKey(key: Key): String        = Serialization.write(key)(serializationFormats)
  }

}
