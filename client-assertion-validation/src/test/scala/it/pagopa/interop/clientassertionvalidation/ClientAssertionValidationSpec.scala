package it.pagopa.interop.clientassertionvalidation

import cats.data.NonEmptyList
import cats.implicits.catsSyntaxOptionId
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimNames
import it.pagopa.interop.clientassertionvalidation.Errors._
import it.pagopa.interop.clientassertionvalidation.SpecData._
import it.pagopa.interop.clientassertionvalidation.SpecUtil._
import it.pagopa.interop.clientassertionvalidation.Validation._
import it.pagopa.interop.clientassertionvalidation.model.Digest
import it.pagopa.interop.commons.utils.{DIGEST_CLAIM, PURPOSE_ID_CLAIM}
import org.scalatest.matchers.should.Matchers._
import org.scalatest.wordspec.AnyWordSpecLike

import java.util.UUID
import scala.jdk.CollectionConverters.MapHasAsJava

class ClientAssertionValidationSpec extends AnyWordSpecLike {

  "Client Assertion Validation" should {
    "fail on wrong client assertion type" in {
      val wrongClientAssertionType = "something-wrong"
      val assertion                = fastClientAssertionJWT()

      validateClientAssertion(Some(clientId.toString), assertion, wrongClientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidAssertionType(wrongClientAssertionType)))
    }

    "fail on wrong grant type" in {
      val wrongGrantType = "something-wrong"
      val assertion      = fastClientAssertionJWT()

      validateClientAssertion(Some(clientId.toString), assertion, clientAssertionType, wrongGrantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidGrantType(wrongGrantType)))
    }

    "fail on malformed assertion" in {
      val malformedAssertion = "something-wrong"

      validateClientAssertion(Some(clientId.toString), malformedAssertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(
        NonEmptyList
          .one(ClientAssertionParseFailed("Invalid serialized unsecured/JWS/JWE object: Missing part delimiters"))
      )
    }

    "fail on wrong audience in assertion" in {
      val assertion = fastClientAssertionJWT(audience = List("another-audience"))

      validateClientAssertion(Some(clientId.toString), assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidAudiences(Set("another-audience"))))
    }

    "fail if client ID in the assertion is different from the parameter client ID" in {
      val wrongClientId = UUID.randomUUID().toString
      val assertion     = fastClientAssertionJWT()

      validateClientAssertion(Some(wrongClientId), assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidSubject(clientId.toString)))
    }

    "fail on wrong client id format" in {
      val wrongClientId = "definitely-not-an-uuid"
      val assertion     = fastClientAssertionJWT()

      validateClientAssertion(Some(wrongClientId), assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidClientIdFormat(wrongClientId)))
    }

    "fail on wrong jwt subject format" in {
      val assertion = fastClientAssertionJWT(subject = "not-an-uuid".some)

      validateClientAssertion(Some(clientId.toString), assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidSubjectFormat("not-an-uuid")))
    }

    "fail on wrong purpose id format" in {
      val assertion = fastClientAssertionJWT(customClaims = Map(PURPOSE_ID_CLAIM -> "not-an-uuid"))

      validateClientAssertion(Some(clientId.toString), assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidPurposeIdFormat("not-an-uuid")))
    }

    "fail when purpose id is empty string" in {
      val assertion = fastClientAssertionJWT(customClaims = Map(PURPOSE_ID_CLAIM -> ""))

      validateClientAssertion(Some(clientId.toString), assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidPurposeIdFormat("")))
    }

    "fail when kid is missing" in {
      val assertion = fastClientAssertionJWT(kid = None)

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(KidNotFound))
    }

    "fail when kid is an empty string" in {
      val assertion = fastClientAssertionJWT(kid = Some(""))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(KidNotFound))
    }

    "fail when kid is aa blank string" in {
      val assertion = fastClientAssertionJWT(kid = Some(" "))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(KidNotFound))
    }

    "fail when kid wrong format" in {
      val assertion = fastClientAssertionJWT(kid = Some("foo/bar"))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(InvalidKidFormat))
    }

    "fail when subject is missing" in {
      val assertion = fastClientAssertionJWT(subject = None)

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(SubjectNotFound))
    }

    "fail when subject is empty string" in {
      val assertion = fastClientAssertionJWT(subject = Some(""))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.one(InvalidSubjectFormat("")))
    }

    "fail when JTI is missing" in {
      val assertion = fastClientAssertionJWT(jti = None)

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(JtiNotFound))
    }

    "fail when issuer is missing" in {
      val assertion = fastClientAssertionJWT(issuer = None)

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(IssuerNotFound))
    }

    "fail when IAT is missing" in {
      val assertion = fastClientAssertionJWT(iat = None)

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(IssuedAtNotFound))
    }

    "fail when EXP is missing" in {
      val assertion = fastClientAssertionJWT(expirationTime = None)

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(ExpirationNotFound))
    }

    "fail on IAT wrong format" in {
      val assertion = fastClientAssertionJWT(customClaims = Map(JWTClaimNames.ISSUED_AT -> "foo"))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(
        NonEmptyList.of(ClientAssertionInvalidClaims("Unexpected type of JSON object member with key iat"))
      )
    }

    "fail on IAT empty string" in {
      val assertion = fastClientAssertionJWT(customClaims = Map(JWTClaimNames.ISSUED_AT -> ""))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(
        NonEmptyList.of(ClientAssertionInvalidClaims("Unexpected type of JSON object member with key iat"))
      )
    }

    "fail on algorithm not allowed" in {
      val ecKey = new ECKeyGenerator(Curve.P_256).generate
      val ecKid = ecKey.computeThumbprint().toString

      val assertion =
        fastClientAssertionJWT(algorithm = "ES256".some, kid = ecKid.some, privateKeyPEM = ecKey.toJSONString.some)

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(AlgorithmNotAllowed("ES256")))
    }

    "fail when digest algorithm is not allowed" in {
      val digest = Digest(alg = "invalid", value = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
      val assertion = fastClientAssertionJWT(customClaims = Map(DIGEST_CLAIM -> digest))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(InvalidHashAlgorithm))
    }

    "fail when digest hash value length is not valid" in {
      val digest    = Digest(alg = "SHA256", value = "tooshort")
      val assertion = fastClientAssertionJWT(customClaims = Map(DIGEST_CLAIM -> digest))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(InvalidHashLength("SHA256")))
    }

    "fail when digest algorithm is missing" in {
      val digest    =
        Map("value" -> "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "foo" -> "bar").asJava
      val assertion = fastClientAssertionJWT(customClaims = Map(DIGEST_CLAIM -> digest))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(DigestClaimNotFound("alg")))
    }

    "fail when digest value is missing" in {
      val digest    = Map("alg" -> "SHA256", "foo" -> "bar").asJava
      val assertion = fastClientAssertionJWT(customClaims = Map(DIGEST_CLAIM -> digest))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(DigestClaimNotFound("value")))
    }

    "fail when digest algorithm is null" in {
      val digest    =
        Map("alg" -> null, "value" -> "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824").asJava
      val assertion = fastClientAssertionJWT(customClaims = Map(DIGEST_CLAIM -> digest))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(DigestClaimNotFound("alg")))
    }

    "fail when digest value is null" in {
      val digest    = Map("alg" -> "SHA256", "value" -> null).asJava
      val assertion = fastClientAssertionJWT(customClaims = Map(DIGEST_CLAIM -> digest))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(DigestClaimNotFound("value")))
    }

    "fail when digest contains too many fields" in {
      val digest    = Map(
        "alg"   -> "SHA256",
        "value" -> "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "foo"   -> "bar"
      ).asJava
      val assertion = fastClientAssertionJWT(customClaims = Map(DIGEST_CLAIM -> digest))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(InvalidDigestClaims))
    }

    "fail when digest claim is not an object" in {
      val digest    = "foo"
      val assertion = fastClientAssertionJWT(customClaims = Map(DIGEST_CLAIM -> digest))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(InvalidDigestFormat("""The "digest" claim is not a JSON object or Map""")))
    }

    "fail on multiple validation errors" in {
      val wrongClientId = UUID.randomUUID().toString
      val assertion     = fastClientAssertionJWT(kid = None)

      validateClientAssertion(Some(wrongClientId), assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe Left(NonEmptyList.of(KidNotFound, InvalidSubject(clientId.toString)))
    }

    "succeed on correct client assertion" in {
      val assertion = fastClientAssertionJWT()

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe a[Right[_, _]]
    }

    "succeed on correct digest in client assertion" in {
      val digest    = Digest(alg = "SHA256", value = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
      val assertion = fastClientAssertionJWT(customClaims = Map(DIGEST_CLAIM -> digest))

      validateClientAssertion(clientId.toString.some, assertion, clientAssertionType, grantType)(
        jwtValidator
      ) shouldBe a[Right[_, _]]
    }
  }

}
