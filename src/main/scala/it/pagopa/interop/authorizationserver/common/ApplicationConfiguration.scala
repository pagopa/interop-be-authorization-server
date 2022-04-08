package it.pagopa.interop.authorizationserver.common

import com.typesafe.config.{Config, ConfigFactory}
import scala.jdk.CollectionConverters.ListHasAsScala

object ApplicationConfiguration {

  lazy val config: Config = ConfigFactory.load()

  lazy val serverPort: Int = config.getInt("interop-authorization-server.port")

  lazy val authorizationManagementURL: String = config.getString("services.authorization-management")

  lazy val rsaPrivatePath: String = config.getString("interop-authorization-server.rsa-private-path")

  lazy val interopIdIssuer: String      = config.getString("interop-authorization-server.jwt.issuer")
  lazy val interopAudience: Set[String] =
    config.getStringList("interop-authorization-server.jwt.audience").asScala.toSet
  lazy val interopTokenDuration: Int    = config.getInt("interop-authorization-server.jwt.duration-seconds")
}
