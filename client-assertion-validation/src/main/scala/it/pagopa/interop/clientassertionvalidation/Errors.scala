package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID
import scala.util.control.NoStackTrace

object Errors {

  abstract class ClientAssertionValidationError(override val code: String, override val msg: String)
      extends ComponentError(code, msg)
      with NoStackTrace

  // These traits are used to cluster validation errors to identify which step failed
  sealed trait ClientAssertionValidationFailure
  sealed trait ClientAssertionSignatureVerificationFailure
  sealed trait PlatformStateVerificationFailure

  final case class InvalidClientIdFormat(clientId: String)
      extends ClientAssertionValidationError("0001", s"Client id $clientId is not a valid UUID")
      with ClientAssertionValidationFailure

  final case class InvalidGrantType(grantType: String)
      extends ClientAssertionValidationError("0002", s"Grant type not valid $grantType")
      with ClientAssertionValidationFailure

  final case class InvalidAssertionType(assertionType: String)
      extends ClientAssertionValidationError("0003", s"Assertion type not valid $assertionType")
      with ClientAssertionValidationFailure

  final case class ClientAssertionParseFailed(reason: String)
      extends ClientAssertionValidationError("0004", s"Client assertion parse failure. Reason: $reason")
      with ClientAssertionValidationFailure

  final case class ClientAssertionInvalidClaims(reason: String)
      extends ClientAssertionValidationError("0005", s"Client assertion validation failure. Reason: $reason")
      with ClientAssertionValidationFailure

  final case class InvalidSubjectFormat(subject: String)
      extends ClientAssertionValidationError("0006", s"Unexpected format for Subject claim value $subject")
      with ClientAssertionValidationFailure

  final case object SubjectNotFound
      extends ClientAssertionValidationError("0007", s"Subject claim not found in JWT")
      with ClientAssertionValidationFailure

  final case class InvalidSubject(subject: String)
      extends ClientAssertionValidationError(
        "0008",
        s"Subject claim value $subject does not correspond to provided client_id parameter"
      )
      with ClientAssertionValidationFailure

  final case class InvalidPurposeIdFormat(purposeId: String)
      extends ClientAssertionValidationError("0009", s"Unexpected format for Purpose Id claim value $purposeId")
      with ClientAssertionValidationFailure

  final case class InvalidAudiences(audiences: Set[String])
      extends ClientAssertionValidationError("0010", s"Invalid audiences: ${audiences.mkString(",")}")
      with ClientAssertionValidationFailure

  final case class InvalidHashLength(alg: String)
      extends ClientAssertionValidationError("0011", s"Invalid hash length for algorithm $alg")
      with ClientAssertionValidationFailure

  case object InvalidHashAlgorithm
      extends ClientAssertionValidationError("0012", s"Invalid hash algorithm")
      with ClientAssertionValidationFailure

  object KidNotFound
      extends ClientAssertionValidationError("0013", s"Kid not found in header")
      with ClientAssertionValidationFailure

  object AlgorithmNotFound
      extends ClientAssertionValidationError("0014", "ALG not found in client assertion")
      with ClientAssertionValidationFailure

  object JtiNotFound
      extends ClientAssertionValidationError("0015", "JTI not found in client assertion")
      with ClientAssertionValidationFailure

  object IssuedAtNotFound
      extends ClientAssertionValidationError("0016", "IAT not found in client assertion")
      with ClientAssertionValidationFailure

  object IssuerNotFound
      extends ClientAssertionValidationError("0017", "ISS not found in client assertion")
      with ClientAssertionValidationFailure

  object ExpirationNotFound
      extends ClientAssertionValidationError("0018", "EXP not found in client assertion")
      with ClientAssertionValidationFailure

  final case class DigestClaimNotFound(claim: String)
      extends ClientAssertionValidationError("0019", s"Digest claim $claim not found")
      with ClientAssertionValidationFailure

  case object InvalidDigestClaims
      extends ClientAssertionValidationError("0020", "Invalid digest claims number")
      with ClientAssertionValidationFailure

  final case class PublicKeyParseFailed(reason: String)
      extends ClientAssertionValidationError("0021", s"Error parsing public key. Reason: $reason")
      with ClientAssertionSignatureVerificationFailure

  final case class ClientAssertionVerificationError(reason: String)
      extends ClientAssertionValidationError("0022", s"Signature verification failed. Reason: $reason")
      with ClientAssertionSignatureVerificationFailure

  object InvalidClientAssertionSignature
      extends ClientAssertionValidationError("0023", s"Invalid client assertion signature")
      with ClientAssertionSignatureVerificationFailure

  final case object PurposeIdNotProvided
      extends ClientAssertionValidationError("0024", "Claim purposeId does not exist in this assertion")
      with PlatformStateVerificationFailure

  final case class PurposeNotFound(clientId: UUID, purposeId: UUID)
      extends ClientAssertionValidationError("0025", s"Purpose $purposeId not found for client $clientId")
      with PlatformStateVerificationFailure

  abstract class InactivePlatformState(override val code: String, override val msg: String)
      extends ClientAssertionValidationError(code, msg)
      with PlatformStateVerificationFailure

  final case class InactivePurpose(state: String) extends InactivePlatformState("0026", s"Purpose is in state $state")

  final case class InactiveEService(state: String)
      extends InactivePlatformState("0027", s"E-Service is in state $state")

  final case class InactiveAgreement(state: String)
      extends InactivePlatformState("0028", s"Agreement is in state $state")

}
