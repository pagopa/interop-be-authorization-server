package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID
import scala.util.control.NoStackTrace

object Errors {

  // TODO Re-number errors
  // TODO Delete unused errors

  abstract class ClientAssertionValidationError(override val code: String, override val msg: String)
      extends ComponentError(code, msg)
      with NoStackTrace

  final case class PurposeNotFound(clientId: UUID, purposeId: UUID)
      extends ClientAssertionValidationError("0003", s"Purpose $purposeId not found for client $clientId")

//  final case class InactivePlatformState(clientId: UUID, reasons: ClientAssertionValidationError*)
//      extends ClientAssertionValidationError(
//        "0004",
//        s"Non-active state for Client $clientId: ${reasons.map(_.getMessage).mkString(", ")}"
//      )

  abstract class InactivePlatformState(override val code: String, override val msg: String)
      extends ClientAssertionValidationError(code, msg)

  final case class InactivePurpose(state: String) extends InactivePlatformState("0005", s"Purpose is in state $state")
  final case class InactiveEService(state: String)
      extends InactivePlatformState("0006", s"E-Service is in state $state")
  final case class InactiveAgreement(state: String)
      extends InactivePlatformState("0007", s"Agreement is in state $state")

  final case object PurposeIdNotProvided
      extends ClientAssertionValidationError("0009", "Claim purposeId does not exist in this assertion")

  final case class InvalidAssertion(message: String)
      extends ClientAssertionValidationError("0010", s"Invalid client assertion. Reasons: $message")

  final case class InvalidAssertionSignature(clientId: UUID, kid: String, reason: String)
      extends ClientAssertionValidationError(
        "0012",
        s"Invalid assertion signature for request with client $clientId and kid $kid. Reason: $reason"
      )

  final case class InvalidClientIdFormat(clientId: String)
      extends ClientAssertionValidationError("0013", s"Client id $clientId is not a valid UUID")

  final case class InvalidGrantType(grantType: String)
      extends ClientAssertionValidationError("0000", s"Grant type not valid $grantType")

  final case class InvalidAssertionType(assertionType: String)
      extends ClientAssertionValidationError("0001", s"Assertion type not valid $assertionType")

  final case class InvalidSubjectFormat(subject: String)
      extends ClientAssertionValidationError("0002", s"Unexpected format for Subject claim value $subject")

  final case object SubjectNotFound extends ClientAssertionValidationError("0003", s"Subject claim not found in JWT")

  final case class InvalidSubject(subject: String)
      extends ClientAssertionValidationError(
        "0004",
        s"Subject claim value $subject does not correspond to provided client_id parameter"
      )

  final case class InvalidPurposeIdFormat(purposeId: String)
      extends ClientAssertionValidationError("0005", s"Unexpected format for Purpose Id claim value $purposeId")

  object KidNotFound extends ClientAssertionValidationError("0006", s"Kid not found in header")

  final case class ClientAssertionValidationFailed(reason: String)
      extends ClientAssertionValidationError("0006", s"Client assertion validation failure. Reason: $reason")

  final case class ClientAssertionParseFailed(reason: String)
      extends ClientAssertionValidationError("0007", s"Client assertion parse failure. Reason: $reason")

  final case class KeyNotFound(clientId: UUID, kid: String, purposeId: Option[UUID])
      extends ClientAssertionValidationError(
        "0008",
        s"Key not found for clientId $clientId, kid $kid ${purposeId.fold("")(id => s"and purposeId $id")}"
      )

  final case class PublicKeyParseFailed(reason: String)
      extends ClientAssertionValidationError("0010", s"Error parsing public key. Reason: $reason")

  object InvalidClientAssertionSignature
      extends ClientAssertionValidationError("0011", s"Invalid client assertion signature")

  final case class InvalidAudiences(audiences: Set[String])
      extends ClientAssertionValidationError("0012", s"Invalid audiences: ${audiences.mkString(",")}")

  // TODO Add id?
  object InactiveAgreementError extends ClientAssertionValidationError("0013", s"Agreement is not ACTIVE")

  object InactiveEServiceError extends ClientAssertionValidationError("0014", s"EService is not ACTIVE")

  object InactivePurposeError extends ClientAssertionValidationError("0015", s"Purpose is not ACTIVE")

  final case class DigestClaimNotFound(claim: String)
      extends ClientAssertionValidationError("", s"Digest claim $claim not found")

  case object InvalidDigestClaims extends ClientAssertionValidationError("", "Invalid digest claims number")

  final case class InvalidHashLength(alg: String)
      extends ClientAssertionValidationError("", s"Invalid hash length for algorithm $alg")

  case object InvalidHashAlgorithm extends ClientAssertionValidationError("", s"Invalid hash algorithm")

  object AlgorithmNotFound  extends ClientAssertionValidationError("", "ALG not found in client assertion")
  object JtiNotFound        extends ClientAssertionValidationError("", "JTI not found in client assertion")
  object IssuedAtNotFound   extends ClientAssertionValidationError("", "IAT not found in client assertion")
  object IssuerNotFound     extends ClientAssertionValidationError("", "ISS not found in client assertion")
  object ExpirationNotFound extends ClientAssertionValidationError("", "EXP not found in client assertion")

  final case class ClientAssertionVerificationError(reason: String)
      extends ClientAssertionValidationError("", s"Signature verification failed. Reason: $reason")

  // TODO
  sealed trait ClientAssertionValidationFailure
  sealed trait ClientAssertionSignatureVerificationFailure
  sealed trait PlatformStateFailure
}
