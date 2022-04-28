package it.pagopa.interop.authorizationserver.common

import com.typesafe.config.{Config, ConfigFactory}

object ApplicationConfiguration {

  val config: Config = ConfigFactory.load()

  val serverPort: Int = config.getInt("authorization-server.port")

  val authorizationManagementURL: String = config.getString("services.authorization-management")

  val rsaPrivatePath: String = config.getString("authorization-server.rsa-private-path")

  val generatedJwtIssuer: String           = config.getString("authorization-server.generated-jwt.issuer")
  val generatedM2mJwtAudience: Set[String] =
    config.getString("authorization-server.generated-jwt.m2m-audience").split(",").toSet.filter(_.nonEmpty)
  val generatedM2mJwtDuration: Int         =
    config.getInt("authorization-server.generated-jwt.m2m-duration-seconds")

  val clientAssertionAudience: Set[String] =
    config.getString("authorization-server.client-assertion-audience").split(",").toSet.filter(_.nonEmpty)

  val jwtQueueUrl: String = config.getString("authorization-server.jwt-queue-url")

  require(generatedM2mJwtAudience.nonEmpty, "Generated JWT Audience cannot be empty")
  require(clientAssertionAudience.nonEmpty, "Client Assertion Audience cannot be empty")
}
