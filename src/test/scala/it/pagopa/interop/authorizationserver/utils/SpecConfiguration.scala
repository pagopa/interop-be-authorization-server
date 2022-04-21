package it.pagopa.interop.authorizationserver.utils

import com.typesafe.config.{Config, ConfigFactory}

trait SpecConfiguration {

  val config: Config = ConfigFactory
    .parseResourcesAnySyntax("application-test")

  val servicePort: Int = config.getInt("authorization-server.port")

  val jwtQueueUrl: String = config.getString("interop-authorization-server.jwt-queue-url")
}

object SpecConfiguration extends SpecConfiguration
