import PagopaVersions._
import Versions._
import sbt._

object Dependencies {

  private[this] object akka {
    lazy val namespace     = "com.typesafe.akka"
    lazy val actorTyped    = namespace                       %% "akka-actor-typed"           % akkaVersion
    lazy val actor         = namespace                       %% "akka-actor"                 % akkaVersion
    lazy val serialization = namespace                       %% "akka-serialization-jackson" % akkaVersion
    lazy val stream        = namespace                       %% "akka-stream"                % akkaVersion
    lazy val clusterTools  = namespace                       %% "akka-cluster-tools"         % akkaVersion
    lazy val http          = namespace                       %% "akka-http"                  % akkaHttpVersion
    lazy val httpJson      = namespace                       %% "akka-http-spray-json"       % akkaHttpVersion
    lazy val httpJson4s    = "de.heikoseeberger"             %% "akka-http-json4s"           % akkaHttpJson4sVersion
    lazy val management    = "com.lightbend.akka.management" %% "akka-management"            % akkaManagementVersion
    lazy val managementLogLevels =
      "com.lightbend.akka.management" %% "akka-management-loglevels-logback" % akkaManagementVersion
    lazy val slf4j         = namespace %% "akka-slf4j"               % akkaVersion
    lazy val httpTestkit   = namespace %% "akka-http-testkit"        % akkaHttpVersion
    lazy val streamTestkit = namespace %% "akka-stream-testkit"      % akkaVersion
    lazy val testkit       = namespace %% "akka-actor-testkit-typed" % akkaVersion

  }

  private[this] object pagopa {
    lazy val namespace = "it.pagopa"

    lazy val authorizationManagement =
      namespace %% "interop-be-authorization-management-client" % authorizationManagementVersion

    lazy val utils        = namespace %% "interop-commons-utils"         % commonsVersion
    lazy val jwt          = namespace %% "interop-commons-jwt"           % commonsVersion
    lazy val queueManager = namespace %% "interop-commons-queue-manager" % commonsVersion
    lazy val rateLimiter  = namespace %% "interop-commons-rate-limiter"  % commonsVersion
    lazy val signer       = namespace %% "interop-commons-signer"        % commonsVersion
    lazy val file         = namespace %% "interop-commons-file-manager"  % commonsVersion
  }

  private[this] object cats {
    lazy val namespace = "org.typelevel"
    lazy val core      = namespace %% "cats-core" % catsVersion
  }

  private[this] object json4s {
    lazy val namespace = "org.json4s"
    lazy val jackson   = namespace %% "json4s-jackson" % json4sVersion
    lazy val ext       = namespace %% "json4s-ext"     % json4sVersion
  }

  private[this] object logback {
    lazy val namespace = "ch.qos.logback"
    lazy val classic   = namespace % "logback-classic" % logbackVersion
  }

  private[this] object mustache {
    lazy val mustache = "com.github.spullara.mustache.java" % "compiler" % mustacheVersion
  }

  private[this] object scalatest {
    lazy val namespace = "org.scalatest"
    lazy val core      = namespace %% "scalatest" % scalatestVersion
  }

  private[this] object scalamock {
    lazy val namespace = "org.scalamock"
    lazy val core      = namespace %% "scalamock" % scalaMockVersion
  }

  private[this] object jackson {
    lazy val namespace   = "com.fasterxml.jackson.core"
    lazy val core        = namespace % "jackson-core"         % jacksonVersion
    lazy val annotations = namespace % "jackson-annotations"  % jacksonVersion
    lazy val databind    = namespace % "jackson-databind"     % jacksonVersion
    lazy val scalaModule = namespace % "jackson-module-scala" % jacksonVersion
  }

  object Jars {
    lazy val overrides: Seq[ModuleID]                 =
      Seq(
        jackson.annotations % Compile,
        jackson.core        % Compile,
        jackson.databind    % Compile,
        jackson.scalaModule % Compile
      )
    lazy val `server`: Seq[ModuleID]                  = Seq(
      // For making Java 12 happy
      "javax.annotation"             % "javax.annotation-api" % "1.3.2" % "compile",
      //
      akka.actor                     % Compile,
      akka.actorTyped                % Compile,
      akka.clusterTools              % Compile,
      akka.http                      % Compile,
      akka.httpJson                  % Compile,
      akka.management                % Compile,
      akka.managementLogLevels       % Compile,
      akka.serialization             % Compile,
      akka.slf4j                     % Compile,
      akka.stream                    % Compile,
      cats.core                      % Compile,
      logback.classic                % Compile,
      mustache.mustache              % Compile,
      pagopa.utils                   % Compile,
      pagopa.jwt                     % Compile,
      pagopa.queueManager            % Compile,
      pagopa.authorizationManagement % Compile,
      pagopa.rateLimiter             % Compile,
      pagopa.signer                  % Compile,
      pagopa.file                    % Compile,
      akka.httpTestkit               % Test,
      akka.streamTestkit             % Test,
      akka.testkit                   % Test,
      scalatest.core                 % Test,
      scalamock.core                 % Test
    )
    lazy val client: Seq[ModuleID]                    =
      Seq(akka.stream, akka.http, akka.httpJson4s, akka.slf4j, json4s.jackson, json4s.ext, pagopa.utils).map(
        _ % Compile
      )
    lazy val clientAssertionValidation: Seq[ModuleID] =
      Seq(pagopa.jwt % Compile, pagopa.authorizationManagement % Compile, scalatest.core % Test)
  }
}
