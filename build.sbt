import ProjectSettings.ProjectFrom
import com.typesafe.sbt.packager.docker.Cmd

ThisBuild / scalaVersion      := "2.13.10"
ThisBuild / organization      := "it.pagopa"
ThisBuild / organizationName  := "Pagopa S.p.A."
ThisBuild / dependencyOverrides ++= Dependencies.Jars.overrides
ThisBuild / version           := ComputeVersion.version
Global / onChangedBuildSource := ReloadOnSourceChanges
ThisBuild / githubOwner       := "pagopa"
ThisBuild / githubRepository  := "interop-be-authorization-server"
ThisBuild / resolvers += Resolver.githubPackages("pagopa")

val clientAssertionValidationModuleName = "client-assertion-validation"

lazy val generateCode = taskKey[Unit]("A task for generating the code starting from the swagger definition")

val packagePrefix = settingKey[String]("The package prefix derived from the uservice name")

packagePrefix := name.value
  .replaceFirst("interop-", "interop.")
  .replaceFirst("be-", "")
  .replaceAll("-", "")

val projectName = settingKey[String]("The project name prefix derived from the uservice name")

projectName := name.value
  .replaceFirst("interop-", "")
  .replaceFirst("be-", "")

generateCode := {
  import sys.process._

  Process(s"""openapi-generator-cli generate -t template/scala-akka-http-server
             |                               -i src/main/resources/interface-specification.yml
             |                               -g scala-akka-http-server
             |                               -p projectName=${projectName.value}
             |                               -p invokerPackage=it.pagopa.${packagePrefix.value}.server
             |                               -p modelPackage=it.pagopa.${packagePrefix.value}.model
             |                               -p apiPackage=it.pagopa.${packagePrefix.value}.api
             |                               -p modelPropertyNaming=original
             |                               -p dateLibrary=java8
             |                               -p entityStrictnessTimeout=15
             |                               -o generated""".stripMargin).!!

  Process(s"""openapi-generator-cli generate -t template/scala-akka-http-client
             |                               -i src/main/resources/interface-specification.yml
             |                               -g scala-akka
             |                               -p projectName=${projectName.value}
             |                               -p invokerPackage=it.pagopa.${packagePrefix.value}.client.invoker
             |                               -p modelPackage=it.pagopa.${packagePrefix.value}.client.model
             |                               -p apiPackage=it.pagopa.${packagePrefix.value}.client.api
             |                               -p modelPropertyNaming=original
             |                               -p dateLibrary=java8
             |                               -o client""".stripMargin).!!

}

(Compile / compile) := ((Compile / compile) dependsOn generateCode).value
(Test / test)       := ((Test / test) dependsOn generateCode).value

cleanFiles += baseDirectory.value / "generated" / "src"
cleanFiles += baseDirectory.value / "generated" / "target"
cleanFiles += baseDirectory.value / "client" / "src"
cleanFiles += baseDirectory.value / "client" / "target"
cleanFiles += baseDirectory.value / clientAssertionValidationModuleName / "target"

val runStandalone = inputKey[Unit]("Run the app using standalone configuration")
runStandalone := {
  task(System.setProperty("config.file", "src/main/resources/application-standalone.conf")).value
  (Compile / run).evaluated
}

lazy val generated =
  project
    .in(file("generated"))
    .settings(
      scalacOptions       := Seq(),
      scalafmtOnCompile   := true,
      libraryDependencies := Dependencies.Jars.`server`,
      publish / skip      := true,
      publish             := (()),
      publishLocal        := (()),
      publishTo           := None
    )
    .setupBuildInfo

lazy val client = project
  .in(file("client"))
  .settings(
    name                := "interop-be-authorization-server-client",
    scalacOptions       := Seq(),
    scalafmtOnCompile   := true,
    libraryDependencies := Dependencies.Jars.client,
    updateOptions       := updateOptions.value.withGigahorse(false),
    Docker / publish    := {}
  )

lazy val clientAssertionValidation = project
  .in(file(clientAssertionValidationModuleName))
  .settings(
    name                := "interop-be-client-assertion-validation",
    libraryDependencies := Dependencies.Jars.clientAssertionValidation,
    scalafmtOnCompile   := true,
    Docker / publish    := {}
  )

lazy val root = (project in file("."))
  .settings(
    name                        := "interop-be-authorization-server",
    Test / parallelExecution    := false,
    scalafmtOnCompile           := true,
    dockerBuildOptions ++= Seq("--network=host"),
    dockerRepository            := Some(System.getenv("ECR_REGISTRY")),
    dockerBaseImage             := "adoptopenjdk:11-jdk-hotspot",
    daemonUser                  := "daemon",
    Docker / version            := (ThisBuild / version).value.replace("-SNAPSHOT", "-latest").toLowerCase,
    Docker / packageName        := s"${name.value}",
    Docker / dockerExposedPorts := Seq(8080),
    Docker / maintainer         := "https://pagopa.it",
    libraryDependencies         := Dependencies.Jars.`server`,
    dockerCommands += Cmd("LABEL", s"org.opencontainers.image.source https://github.com/pagopa/${name.value}")
  )
  .aggregate(client, clientAssertionValidation)
  .dependsOn(generated, clientAssertionValidation, clientAssertionValidation % "test->test")
  .enablePlugins(JavaAppPackaging)
  .enablePlugins(DockerPlugin)
  .enablePlugins(NoPublishPlugin)
  .setupBuildInfo

Test / fork := true
Test / javaOptions += "-Dconfig.file=src/test/resources/application-test.conf"
