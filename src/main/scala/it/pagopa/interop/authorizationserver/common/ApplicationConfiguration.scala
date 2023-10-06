package it.pagopa.interop.authorizationserver.common

import com.typesafe.config.{Config, ConfigFactory}
import it.pagopa.interop.commons.ratelimiter.model.LimiterConfig

import java.util.concurrent.TimeUnit
import scala.concurrent.duration.FiniteDuration

object ApplicationConfiguration {

  val config: Config = ConfigFactory.load()

  val serverPort: Int = config.getInt("authorization-server.port")

  val authorizationManagementURL: String = config.getString("services.authorization-management")

  val generatedJwtIssuer: String           = config.getString("authorization-server.generated-jwt.issuer")
  val generatedM2mJwtAudience: Set[String] =
    config.getString("authorization-server.generated-jwt.m2m-audience").split(",").toSet.filter(_.nonEmpty)
  val generatedM2mJwtDuration: Int         =
    config.getInt("authorization-server.generated-jwt.m2m-duration-seconds")

  val clientAssertionAudience: Set[String] =
    config.getString("authorization-server.client-assertion-audience").split(",").toSet.filter(_.nonEmpty)

  val jwtQueueUrl: String           = config.getString("authorization-server.jwt-queue-url")
  val jwtFallbackBucketPath: String = config.getString("authorization-server.jwt-fallback-bucket")

  val rsaKeysIdentifiers: Set[String] =
    config.getString("authorization-server.rsa-keys-identifiers").split(",").toSet.filter(_.nonEmpty)

  val ecKeysIdentifiers: Set[String] =
    config.getString("authorization-server.ec-keys-identifiers").split(",").toSet.filter(_.nonEmpty)

  val rateLimiterConfigs: LimiterConfig = {
    val rateInterval = config.getDuration("authorization-server.rate-limiter.rate-interval")
    val timeout      = config.getDuration("authorization-server.rate-limiter.timeout")

    LimiterConfig(
      limiterGroup = config.getString("authorization-server.rate-limiter.limiter-group"),
      maxRequests = config.getInt("authorization-server.rate-limiter.max-requests"),
      burstPercentage = config.getDouble("authorization-server.rate-limiter.burst-percentage"),
      rateInterval = FiniteDuration(rateInterval.toMillis, TimeUnit.MILLISECONDS),
      redisHost = config.getString("authorization-server.rate-limiter.redis-host"),
      redisPort = config.getInt("authorization-server.rate-limiter.redis-port"),
      timeout = FiniteDuration(timeout.toMillis, TimeUnit.MILLISECONDS)
    )
  }

  require(generatedM2mJwtAudience.nonEmpty, "Generated JWT Audience cannot be empty")
  require(clientAssertionAudience.nonEmpty, "Client Assertion Audience cannot be empty")
  require(
    rsaKeysIdentifiers.nonEmpty || ecKeysIdentifiers.nonEmpty,
    "You MUST provide at least one signing key (either RSA or EC)"
  )

}
