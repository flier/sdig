lazy val commonSettings = Seq(
    name := "sdig",
    version := "1.0",
    scalaVersion := "2.12.1",
    test in assembly := {}
)

lazy val root = (project in file("."))
    .settings(commonSettings: _*)
    .settings(
        mainClass := Some("com.nexusguard.sdig.Main")
    )

resolvers += Resolver.mavenLocal

libraryDependencies ++= Seq(
    "com.typesafe.scala-logging" %% "scala-logging" % "3.5.0",
    "ch.qos.logback" % "logback-classic" % "1.1.7",

    "com.github.scopt" %% "scopt" % "3.5.0",
    "com.google.guava" % "guava" % "21.0",
    "org.apache.commons" % "commons-pool2" % "2.4.2",

    "io.netty" % "netty-all" % "4.1.9.Final"
)

trapExit := false
