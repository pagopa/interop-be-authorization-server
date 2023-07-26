package it.pagopa.interop.clientassertionvalidation

import it.pagopa.interop.commons.utils.errors.ComponentError

import java.util.UUID
import scala.util.control.NoStackTrace

object Errors {

  // Warning: Do not change error codes

  abstract class ClientAssertionValidationError(override val code: String, override val msg: String)
      extends ComponentError(code, msg)
      with NoStackTrace

  // These traits are used to cluster validation errors to identify which step failed
  sealed trait ClientAssertionValidationFailure
  sealed trait ClientAssertionSignatureVerificationFailure
  sealed trait PlatformStateVerificationFailure

  final case class InvalidClientIdFormat(clientId: String)
      extends ClientAssertionValidationError("8001", s"Client id $clientId is not a valid UUID")
      with ClientAssertionValidationFailure

  final case class InvalidGrantType(grantType: String)
      extends ClientAssertionValidationError("8002", s"Grant type not valid $grantType")
      with ClientAssertionValidationFailure

  final case class InvalidAssertionType(assertionType: String)
      extends ClientAssertionValidationError("8003", s"Assertion type not valid $assertionType")
      with ClientAssertionValidationFailure

  final case class ClientAssertionParseFailed(reason: String)
      extends ClientAssertionValidationError("8004", s"Client assertion parse failure. Reason: $reason")
      with ClientAssertionValidationFailure

  final case class ClientAssertionInvalidClaims(reason: String)
      extends ClientAssertionValidationError("8005", s"Client assertion validation failure. Reason: $reason")
      with ClientAssertionValidationFailure

  final case class InvalidSubjectFormat(subject: String)
      extends ClientAssertionValidationError("8006", s"Subject claim $subject is not a valid UUID")
      with ClientAssertionValidationFailure

  case object SubjectNotFound
      extends ClientAssertionValidationError("8007", s"Subject claim not found in JWT")
      with ClientAssertionValidationFailure

  final case class InvalidSubject(subject: String)
      extends ClientAssertionValidationError(
        "8008",
        s"Subject claim value $subject does not correspond to provided client_id parameter"
      )
      with ClientAssertionValidationFailure

  final case class InvalidPurposeIdFormat(purposeId: String)
      extends ClientAssertionValidationError("8009", s"Purpose Id claim $purposeId is not a valid UUID")
      with ClientAssertionValidationFailure

  final case class InvalidAudiences(audiences: Set[String])
      extends ClientAssertionValidationError("8010", s"Invalid audiences: ${audiences.mkString(",")}")
      with ClientAssertionValidationFailure

  final case class InvalidHashLength(alg: String)
      extends ClientAssertionValidationError("8011", s"Invalid hash length for algorithm $alg")
      with ClientAssertionValidationFailure

  case object InvalidHashAlgorithm
      extends ClientAssertionValidationError("8012", s"Invalid hash algorithm")
      with ClientAssertionValidationFailure

  object KidNotFound
      extends ClientAssertionValidationError("8013", s"Kid not found in header")
      with ClientAssertionValidationFailure

  object AlgorithmNotFound
      extends ClientAssertionValidationError("8014", "ALG not found in client assertion")
      with ClientAssertionValidationFailure

  object JtiNotFound
      extends ClientAssertionValidationError("8015", "JTI not found in client assertion")
      with ClientAssertionValidationFailure

  object IssuedAtNotFound
      extends ClientAssertionValidationError("8016", "IAT not found in client assertion")
      with ClientAssertionValidationFailure

  object IssuerNotFound
      extends ClientAssertionValidationError("8017", "ISS not found in client assertion")
      with ClientAssertionValidationFailure

  object ExpirationNotFound
      extends ClientAssertionValidationError("8018", "EXP not found in client assertion")
      with ClientAssertionValidationFailure

  final case class DigestClaimNotFound(claim: String)
      extends ClientAssertionValidationError("8019", s"Digest claim $claim not found")
      with ClientAssertionValidationFailure

  case object InvalidDigestClaims
      extends ClientAssertionValidationError("8020", "Invalid digest claims number")
      with ClientAssertionValidationFailure

  final case class PublicKeyParseFailed(reason: String)
      extends ClientAssertionValidationError("8021", s"Error parsing public key. Reason: $reason")
      with ClientAssertionSignatureVerificationFailure

  final case class ClientAssertionVerificationError(reason: String)
      extends ClientAssertionValidationError("8022", s"Signature verification failed. Reason: $reason")
      with ClientAssertionSignatureVerificationFailure

  object InvalidClientAssertionSignature
      extends ClientAssertionValidationError("8023", s"Invalid client assertion signature")
      with ClientAssertionSignatureVerificationFailure

  case object PurposeIdNotProvided
      extends ClientAssertionValidationError("8024", "Claim purposeId does not exist in this assertion")
      with PlatformStateVerificationFailure

  final case class PurposeNotFound(clientId: UUID, purposeId: UUID)
      extends ClientAssertionValidationError("8025", s"Purpose $purposeId not found for client $clientId")
      with PlatformStateVerificationFailure

  abstract class InactivePlatformState(override val code: String, override val msg: String)
      extends ClientAssertionValidationError(code, msg)
      with PlatformStateVerificationFailure

  object InactivePurpose   extends InactivePlatformState("8026", "Purpose is not active")
  object InactiveEService  extends InactivePlatformState("8027", "E-Service is not active")
  object InactiveAgreement extends InactivePlatformState("8028", "Agreement is not active")

  final case class AlgorithmNotAllowed(algorithm: String)
      extends ClientAssertionValidationError("8029", s"Algorithm $algorithm is not allowed")
      with ClientAssertionValidationFailure

  final case class InvalidPurposeIdClaimFormat(reason: String)
      extends ClientAssertionValidationError("8030", s"Unexpected format for Purpose Id. Reason: $reason")
      with ClientAssertionValidationFailure

  final case class InvalidAudienceFormat(reason: String)
      extends ClientAssertionValidationError("8031", s"Invalid format for audience claim. Reason: $reason")
      with ClientAssertionValidationFailure

  final case class InvalidDigestFormat(reason: String)
      extends ClientAssertionValidationError("8032", s"Invalid format for digest claim. Reason: $reason")
      with ClientAssertionValidationFailure

  object InvalidKidFormat
      extends ClientAssertionValidationError("8033", s"Unexpected format for kid")
      with ClientAssertionValidationFailure

}
