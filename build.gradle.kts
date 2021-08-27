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
        classpath("com.taktik.gradle:gradle-plugin-maven-repository:1.0.2")
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
    implementation(
        group = "org.jetbrains.kotlinx",
        name = "kotlinx-coroutines-reactive",
        version = kotlinCoroutinesVersion
    )
    implementation(
        group = "org.jetbrains.kotlinx",
        name = "kotlinx-coroutines-reactor",
        version = kotlinCoroutinesVersion
    )

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
    dependsOn("apiGenerate", "build")
}

tasks.register("apiGenerate", Jar::class) {
    doLast {
        javaexec {
            main = "-jar"
            args = listOf(
                "${rootDir}/openapi-generator-cli.jar", "generate",
                "-i", "${rootDir}/icure-openapi-spec.json",
                "-g", "kotlin",
                "-o", "$rootDir",

                "--model-package", "io.icure.kraken.client.models",
                "--api-package", "io.icure.kraken.client.apis",
                "--package-name", "io.icure.kraken.client",
                "--group-id", "io.icure",
                "--artifact-id", project.name,
                "--artifact-version", "0.0.1-SNAPSHOT",
                "--template-dir", "$rootDir/openApiTemplates",
                "--additional-properties", "useCoroutines=true,serializationLibrary=jackson"
            )
        }
    }
    dependsOn.add("download-openapi-spec") // required due to https://github.com/OpenAPITools/openapi-generator/issues/8255
    finalizedBy("apply-custom-fixes", "delete-unused-filter-files")
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

        // Use manually added filter classes instead of the generated ones
        val replaceFilterDtos = mapOf(
            "AbstractFilterDtoInvoice" to "io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.InvoiceDto>",
            "AbstractFilterDtoService" to "io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.ServiceDto>",
            "AbstractFilterDtoPatient" to "io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.PatientDto>",
            "AbstractFilterDtoHealthElement" to "io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.HealthElementDto>",
            "AbstractFilterDtoContact" to "io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.ContactDto>",
            "AbstractFilterDtoCode" to "io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.CodeDto>",

            "import io.icure.kraken.client.models.AbstractFilterDtoContact" to "",
            "import io.icure.kraken.client.models.AbstractFilterDtoCode" to "",
            "import io.icure.kraken.client.models.AbstractFilterDtoHealthElement" to "",
            "import io.icure.kraken.client.models.AbstractFilterDtoPatient" to "",
            "import io.icure.kraken.client.models.AbstractFilterDtoService" to "",
            "import io.icure.kraken.client.models.AbstractFilterDtoInvoice" to ""
        )

        // in Folders
        val folders = listOf("${rootDir}/src/main/kotlin/io/icure/kraken/client/apis", "${rootDir}/src/main/kotlin/io/icure/kraken/client/models")

        for (folder in folders) {
                    for ((match, replace) in replaceFilterDtos) {
            ant.withGroovyBuilder {
                "replaceregexp"(
                    "match" to "(?<!\\.)$match",
                    "replace" to replace,
                    "flags" to "g",
                    "byline" to "true"
                ) {
                    "fileset"(
                        "dir" to File(folder),
                        "includes" to "*.kt"
                    )
                }
            }
        }
        }
    }
}

tasks.create<Delete>("delete-unused-filter-files") {
    delete(File("$rootDir/src/main/kotlin/io/icure/kraken/client/models/AbstractFilterDtoInvoice.kt"))
    delete(File("$rootDir/src/main/kotlin/io/icure/kraken/client/models/AbstractFilterDtoService.kt"))
    delete(File("$rootDir/src/main/kotlin/io/icure/kraken/client/models/AbstractFilterDtoPatient.kt"))
    delete(File("$rootDir/src/main/kotlin/io/icure/kraken/client/models/AbstractFilterDtoHealthElement.kt"))
    delete(File("$rootDir/src/main/kotlin/io/icure/kraken/client/models/AbstractFilterDtoContact.kt"))
    delete(File("$rootDir/src/main/kotlin/io/icure/kraken/client/models/AbstractFilterDtoCode.kt"))
}
