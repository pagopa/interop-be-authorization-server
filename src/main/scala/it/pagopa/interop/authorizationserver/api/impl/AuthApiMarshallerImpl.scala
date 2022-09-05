package it.pagopa.interop.authorizationserver.api.impl

import akka.http.scaladsl.marshalling.ToEntityMarshaller
import it.pagopa.interop.authorizationserver.api.AuthApiMarshaller
import it.pagopa.interop.authorizationserver.model.{ClientCredentialsResponse, Problem}

object AuthApiMarshallerImpl extends AuthApiMarshaller {

  override implicit def toEntityMarshallerClientCredentialsResponse: ToEntityMarshaller[ClientCredentialsResponse] =
    sprayJsonMarshaller[ClientCredentialsResponse]

  override implicit def toEntityMarshallerProblem: ToEntityMarshaller[Problem] = entityMarshallerProblem

}
