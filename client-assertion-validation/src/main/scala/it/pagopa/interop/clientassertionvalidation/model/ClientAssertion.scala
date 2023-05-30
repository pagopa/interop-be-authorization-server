package it.pagopa.interop.clientassertionvalidation.model

import java.util.UUID

final case class ClientAssertion(
  kid: String,
  alg: String,
  sub: UUID, // ClientId
  purposeId: Option[UUID],
  jti: String,
  iat: Long,
  iss: String,
  aud: Set[String],
  exp: Long,
  raw: String,
  digest: Option[Digest]
)
