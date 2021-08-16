val kotlinVersion = "1.5.21"
val kotlinCoroutinesVersion = "1.5.1"
val jacksonVersion = "2.12.4"

plugins {
    kotlin("jvm") version "1.5.21"
    kotlin("kapt") version "1.5.21"
}

buildscript {
    repositories {
        mavenCentral()
        maven { url = uri("https://maven.taktik.be/content/groups/public") }
    }
    dependencies {
        classpath("com.taktik.gradle:gradle-plugin-git-version:2.0.2")
        classpath ("com.taktik.gradle:gradle-plugin-maven-repository:1.0.2")
    }
    plugins {
        id("org.openapi.generator") version "5.2.0"
    }
}

apply(plugin = "git-version")
apply(plugin = "maven-repository")
val gitVersion: String? by project

group = "io.icure"
version = gitVersion ?: "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
    maven {
        url = uri("https://maven.taktik.be/content/groups/public")
    }
}

dependencies {
    api(group = "com.github.pozo", name = "mapstruct-kotlin", version = "1.4.0.0")
    kapt(group = "com.github.pozo", name = "mapstruct-kotlin-processor", version = "1.4.0.0")

    implementation(group = "org.jetbrains.kotlin", name = "kotlin-stdlib", version = kotlinVersion)

    implementation(group = "org.jetbrains.kotlinx", name = "kotlinx-coroutines-core", version = kotlinCoroutinesVersion)
    implementation(group = "org.jetbrains.kotlinx", name = "kotlinx-coroutines-reactor", version = kotlinCoroutinesVersion)

    implementation(group = "com.fasterxml.jackson.core", name = "jackson-core", version = jacksonVersion)
    implementation(group = "com.fasterxml.jackson.core", name = "jackson-databind", version = jacksonVersion)
    implementation(group = "com.fasterxml.jackson.module", name = "jackson-module-kotlin", version = jacksonVersion)
    implementation(group = "com.fasterxml.jackson.datatype", name = "jackson-datatype-jsr310", version = jacksonVersion)
    implementation(group = "io.icure", name = "async-jackson-http-client", version = "bc6844fb0b")
    implementation(group = "javax.inject", name = "javax.inject", version = "1")
    implementation(group = "org.mapstruct", name = "mapstruct", version = "1.4.2.Final")
    implementation(group = "com.github.ben-manes.caffeine", name = "caffeine", version = "3.0.3")

    // Bouncy Castle
    implementation(group = "org.bouncycastle", name = "bcprov-jdk15on", version = "1.69")
    implementation(group = "org.bouncycastle", name = "bcmail-jdk15on", version = "1.69")

    testImplementation(group = "io.kotlintest", name = "kotlintest", version = "2.0.7")
    testImplementation(group = "org.junit.jupiter", name = "junit-jupiter", version = "5.7.0")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

tasks.getByName("publish") {
    dependsOn("openApiGenerate", "build")
    mustRunAfter("apply-custom-fixes")
}

tasks.openApiGenerate {
    apiPackage.set("io.icure.kraken.client.apis")
    modelPackage.set("io.icure.kraken.client.models")
    packageName.set("io.icure.kraken.client")
    groupId.set("io.icure")
    id.set(rootProject.name)
    version.set("0.0.1-SNAPSHOT")
    additionalProperties.put("useCoroutines", true)
    additionalProperties.put("serializationLibrary", "jackson")
    generatorName.set("kotlin")
    templateDir.set("$rootDir/openApiTemplates")
    inputSpec.set("${rootDir}/icure-openapi-spec.json")
    outputDir.set("$rootDir")
    dependsOn.add("download-openapi-spec") // required due to https://github.com/OpenAPITools/openapi-generator/issues/8255

    finalizedBy( "apply-custom-fixes") // "contract" is not in reserved words list
}

tasks.register("download-openapi-spec") {
    doLast {
        val destFile = File("${rootDir}/icure-openapi-spec.json")
        val url = "https://kraken.icure.dev/v3/api-docs"
        ant.invokeMethod("get", mapOf("src" to url, "dest" to destFile))
    }
}

tasks.register("apply-custom-fixes") {
    doLast {
        // contract is a kotlin keyword => escape it with ``
        ant.withGroovyBuilder {
            "replaceregexp"("match" to "contract\\(", "replace" to "`contract`(", "flags" to "g", "byline" to "true") {
                "fileset"(
                    "dir" to File("${rootDir}/src/main/kotlin/io/icure/kraken/client/models"),
                    "includes" to "PatientDto.kt"
                )
            }
        }
    }
}

tasks.test {
}
