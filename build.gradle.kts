val kotlinVersion = "1.4.21"
val kotlinCoroutinesVersion = "1.4.2"
val jacksonVersion = "2.12.4"

plugins {
    kotlin("jvm") version "1.4.21"
    kotlin("kapt") version "1.4.21"
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
    api(group = "com.github.pozo", name = "mapstruct-kotlin", version = "1.3.1.2")
    kapt(group = "com.github.pozo", name = "mapstruct-kotlin-processor", version = "1.3.1.2")

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
    implementation(group = "io.icure", name = "async-jackson-http-client", version = "0.1.4-6cab16ec6e")
    implementation(group = "javax.inject", name = "javax.inject", version = "1")
    implementation(group = "org.mapstruct", name = "mapstruct", version = "1.3.1.Final")
    implementation(group = "com.github.ben-manes.caffeine", name = "caffeine", version = "3.0.3")

    implementation(group = "io.projectreactor.netty", name = "reactor-netty", version = "1.0.10")
    // Bouncy Castle
    implementation(group = "org.bouncycastle", name = "bcprov-jdk15on", version = "1.69")
    implementation(group = "org.bouncycastle", name = "bcmail-jdk15on", version = "1.69")

    testImplementation(group = "io.kotlintest", name = "kotlintest", version = "2.0.7")
    testImplementation(group = "org.junit.jupiter", name = "junit-jupiter", version = "5.7.0")
    testImplementation(group = "com.willowtreeapps.assertk", name = "assertk-jvm", version = "0.24")
}

//java{
//    sourceSets{
//        main{
//            java{
//                exclude("**/AccesslogApiTest.kt",
//                    "**/AgendaApiTest.kt",
//                    "**/ApplicationsettingsApiTest.kt",
//                    "**/ArticleApiTest.kt",
//                    "**/AuthApiTest.kt",
//                    "**/BeefactApiTest.kt",
//                    "**/BekmehrApiTest.kt",
//                    "**/BemikronoApiTest.kt",
//                    "**/BeresultexportApiTest.kt",
//                    "**/BeresultimportApiTest.kt",
//                    "**/Besamv2ApiTest.kt",
//                    "**/CalendarItemApiTest.kt",
//                    "**/CalendarItemTypeApiTest.kt",
//                    "**/ClassificationApiTest.kt",
//                    "**/ClassificationTemplateApiTest.kt",
//                    "**/CodeApiTest.kt",
//                    "**/ContactApiTest.kt",
//                    "**/DoctemplateApiTest.kt",
//                    "**/DocumentApiTest.kt",
//                    "**/EntityrefApiTest.kt",
//                    "**/EntitytemplateApiTest.kt",
//                    "**/FormApiTest.kt",
//                    "**/FrontendmigrationApiTest.kt",
//                    "**/GroupApiTest.kt",
//                    "**/HcpartyApiTest.kt",
//                    "**/HelementApiTest.kt",
//                    "**/IcureApiTest.kt",
//                    "**/InsuranceApiTest.kt",
//                    "**/InvoiceApiTest.kt",
//                    "**/KeywordApiTest.kt",
//                    "**/MedexApiTest.kt",
//                    "**/MedicallocationApiTest.kt",
//                    "**/MessageApiTest.kt",
//                    "**/PlaceApiTest.kt",
//                    "**/PubsubApiTest.kt",
//                    "**/ReceiptApiTest.kt",
//                    "**/TarificationApiTest.kt",
//                    "**/TimeTableApiTest.kt",
//                    "**/TmpApiTest.kt",
//                    "**/UserApiTest.kt")
//
//                excludes.forEach { print("Excluded : ${it}${System.lineSeparator()}") }
//            }
//        }
//    }
//}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

tasks.getByName("publish") {
    dependsOn("apiGenerate", "build")
}

tasks.register("apiGenerate", Jar::class) {
    inputs.files(fileTree("openApiTemplates"))
        .withPropertyName("sourceFiles")
        .withPathSensitivity(PathSensitivity.RELATIVE)
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
        val url = "http://localhost:16043/v3/api-docs/v2"
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
        val folders = listOf(
            "${rootDir}/src/main/kotlin/io/icure/kraken/client/apis",
            "${rootDir}/src/main/kotlin/io/icure/kraken/client/models"
        )

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
