addSbtPlugin("com.eed3si9n" % "sbt-buildinfo" % "0.11.0")

addSbtPlugin("org.scoverage" % "sbt-scoverage" % "2.0.4")

addSbtPlugin("com.github.sbt" % "sbt-native-packager" % "1.9.11")

addSbtPlugin("io.github.davidgregory084" % "sbt-tpolecat" % "0.4.1")

addSbtPlugin("org.scalameta" % "sbt-scalafmt" % "2.4.6")

libraryDependencies += "com.thesamet.scalapb" %% "compilerplugin" % "0.11.12"

addCompilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1")
