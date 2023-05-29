package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.clientassertionvalidation.Errors.{ClientAssertionValidationError, DigestClaimNotFound}

import java.util
import scala.jdk.CollectionConverters.MapHasAsJava

final case class Digest(alg: String, value: String) {
  import Digest.{algClaim, valueClaim}
  def toJavaMap: util.Map[String, String] = Map(algClaim -> alg, valueClaim -> value).asJava
}

object Digest {
  final val algClaim   = "alg"
  final val valueClaim = "value"

  def create(rawDigest: Map[String, AnyRef]): Either[ClientAssertionValidationError, Digest] = for {
    alg   <- rawDigest.get(algClaim).map(_.toString).toRight(DigestClaimNotFound(algClaim))
    value <- rawDigest.get(valueClaim).map(_.toString).toRight(DigestClaimNotFound(valueClaim))
  } yield Digest(alg, value)
}