plugins {
    kotlin("jvm") version "1.9.0"
    application
//    id("com.ncorti.ktfmt.gradle") version "0.19.0"
}

group = "com.bcsonto"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.pcap4j:pcap4j-core:1.8.2")
    implementation("org.pcap4j:pcap4j-packetfactory-static:1.8.2")
    implementation("ch.qos.logback:logback-classic:1.5.6")
    implementation("io.github.microutils:kotlin-logging-jvm:2.0.11")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("com.github.ajalt.clikt:clikt:5.0.1")
    // optional support for rendering markdown in help messages
    implementation("com.github.ajalt.mordant:mordant:3.0.0")
    implementation("com.github.ajalt.clikt:clikt-markdown:5.0.1")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(8)
}

application {
    mainClass.set("MainKt")
}
