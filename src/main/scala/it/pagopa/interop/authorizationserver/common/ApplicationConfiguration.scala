package it.pagopa.interop.authorizationserver.common

import com.typesafe.config.{Config, ConfigFactory}

object ApplicationConfiguration {

  lazy val config: Config = ConfigFactory.load()

  lazy val serverPort: Int = config.getInt("interop-authorization-server.port")

  lazy val authorizationManagementURL: String = config.getString("services.authorization-management")

  lazy val rsaPrivatePath: String = config.getString("interop-authorization-server.rsa-private-path")

  lazy val generatedJwtIssuer: String           = config.getString("interop-authorization-server.generated-jwt.issuer")
  lazy val generatedM2mJwtAudience: Set[String] =
    config.getString("interop-authorization-server.generated-jwt.m2m-audience").split(",").toSet
  lazy val generatedM2mJwtDuration: Int         =
    config.getInt("interop-authorization-server.generated-jwt.m2m-duration-seconds")

  lazy val clientAssertionAudience: Set[String] =
    config.getString("interop-authorization-server.client-assertion-audience").split(",").toSet
}
