lazy val root = (project in file("."))
    .settings(
        name := "sdig",
        version := "1.0",
        scalaVersion := "2.12.1"
    )

mainClass in (Compile, run) := Some("com.nexusguard.sdig.Main")

libraryDependencies ++= Seq(
    "com.typesafe.scala-logging" %% "scala-logging" % "3.5.0",
    "ch.qos.logback" % "logback-classic" % "1.1.7",

    "com.github.scopt" %% "scopt" % "3.5.0",
    "com.google.guava" % "guava" % "21.0",

    "io.netty" % "netty-all" % "4.1.9.Final"
)

trapExit := false
