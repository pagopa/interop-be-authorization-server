package it.pagopa.interop.authorizationserver
import com.typesafe.config.{Config, ConfigFactory}

trait SpecConfiguration {

  val config: Config = ConfigFactory
    .parseResourcesAnySyntax("application-test")

  def servicePort: Int = config.getInt("authorization-server.port")
}

object SpecConfiguration extends SpecConfiguration
