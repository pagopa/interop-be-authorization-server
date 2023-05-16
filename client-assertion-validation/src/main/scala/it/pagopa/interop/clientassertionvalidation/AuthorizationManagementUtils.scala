package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.authorizationmanagement.client.api.EnumsSerializers
import it.pagopa.interop.authorizationmanagement.client.invoker.Serializers
import it.pagopa.interop.authorizationmanagement.client.model.Key
import org.json4s.jackson.Serialization
import org.json4s.{DefaultFormats, Formats}

object AuthorizationManagementUtils {

  private def serializationFormats: Formats =
    DefaultFormats ++ Serializers.all ++ EnumsSerializers.all

  def serializeKey(key: Key): String = Serialization.write(key)(serializationFormats)
}
