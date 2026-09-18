plugins {
    java
}

group = "top.pkumc"
version = (groovy.json.JsonSlurper().parse(file("src/main/resources/velocity-plugin.json")) as Map<*, *>)["version"] as String

val velocityJar = files(System.getenv("VELOCITY_JAR") ?: "../../velocity/velocity-4.2.1-SNAPSHOT-31.jar")

dependencies {
    compileOnly(velocityJar)
    testImplementation(velocityJar)
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

tasks.jar {
    archiveFileName.set("TrustedBridgeAuth-${project.version}.jar")
}

tasks.withType<JavaCompile>().configureEach { options.release.set(21) }

val regressionTest by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("top.pkumc.trustedbridgeauth.HandoffProtocolTest")
}
tasks.check { dependsOn(regressionTest) }

val bridgeStatusTest by tasks.registering(JavaExec::class) {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("top.pkumc.trustedbridgeauth.BridgeStatusTest")
}
tasks.check { dependsOn(bridgeStatusTest) }
