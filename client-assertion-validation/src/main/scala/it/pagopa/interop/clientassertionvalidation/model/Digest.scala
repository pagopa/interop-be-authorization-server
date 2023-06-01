package it.pagopa.interop.clientassertionvalidation.model

import it.pagopa.interop.clientassertionvalidation.Errors.DigestClaimNotFound
import it.pagopa.interop.clientassertionvalidation.utils.ValidationTypes.ValidationFailure

import java.util
import scala.jdk.CollectionConverters.MapHasAsJava

final case class Digest(alg: String, value: String) {
  import Digest.{algClaim, valueClaim}
  def toJavaMap: util.Map[String, String] = Map(algClaim -> alg, valueClaim -> value).asJava
}

object Digest {
  final val algClaim   = "alg"
  final val valueClaim = "value"

  def create(rawDigest: Map[String, AnyRef]): Either[ValidationFailure, Digest] = for {
    alg   <- rawDigest.get(algClaim).flatMap(Option(_).map(_.toString)).toRight(DigestClaimNotFound(algClaim))
    value <- rawDigest.get(valueClaim).flatMap(Option(_).map(_.toString)).toRight(DigestClaimNotFound(valueClaim))
  } yield Digest(alg, value)
}
