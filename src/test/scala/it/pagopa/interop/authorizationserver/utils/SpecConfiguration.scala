package it.pagopa.interop.authorizationserver.utils

import com.typesafe.config.{Config, ConfigFactory}

trait SpecConfiguration {

  val config: Config = ConfigFactory.parseResourcesAnySyntax("application-test")

  val servicePort: Int = config.getInt("authorization-server.port")
}

object SpecConfiguration extends SpecConfiguration
