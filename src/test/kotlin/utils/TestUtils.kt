package utils

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.SingletonSupport
import io.icure.kraken.client.models.CodeDto
import kotlinx.coroutines.reactive.awaitFirstOrNull
import reactor.core.publisher.Mono
import reactor.netty.http.client.HttpClient
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import kotlin.random.Random

@JsonIgnoreProperties(ignoreUnknown = true)
private data class IdWithRev(@field:JsonProperty("_id") val id: String, @field:JsonProperty("_rev") val rev: String)

suspend fun removeEntities(ids: List<String>, dbUser: String, dbPwd: String, dbUrl: String, dbPrefix: String) {
    val objectMapper = ObjectMapper().registerModule(
        KotlinModule.Builder()
            .nullIsSameAsDefault(nullIsSameAsDefault = false)
            .reflectionCacheSize(reflectionCacheSize = 512)
            .nullToEmptyMap(nullToEmptyMap = false)
            .nullToEmptyCollection(nullToEmptyCollection = false)
            .singletonSupport(singletonSupport = SingletonSupport.DISABLED)
            .strictNullChecks(strictNullChecks = false)
            .build()
    )

    val auth = "Basic ${java.util.Base64.getEncoder().encodeToString("${dbUser}:${dbPwd}".toByteArray())}"
    val client = HttpClient.create().headers { h ->
        h.set("Authorization", auth)
        h.set("Content-type", "application/json")
    }

    ids.forEach { id ->
        client.get()
            .uri("${dbUrl}/${dbPrefix}-base/${URLEncoder.encode(id, Charsets.UTF_8)}")
            .responseSingle { response, buffer ->
                if (response.status().code() < 400) {
                    buffer.asString(StandardCharsets.UTF_8).mapNotNull {
                        objectMapper?.readValue(it, object : TypeReference<IdWithRev>() {})
                    }.flatMap {
                        it?.let {
                            client.delete().uri("${dbUrl}/${dbPrefix}-base/${URLEncoder.encode(id, Charsets.UTF_8)}?rev=${URLEncoder.encode(it.rev, Charsets.UTF_8)}").response()
                        } ?: Mono.empty()
                    }
                } else Mono.empty()
            }.awaitFirstOrNull()
    }
}


class CodeBatchGenerator {

    private val alphabet: List<Char> = ('a'..'z').toList() + ('A'..'Z') + ('0'..'9')
    private val languages = listOf("en", "fr", "nl")
    private val types = listOf("SNOMED", "LOINC", "TESTCODE", "DEEPSECRET")
    private val regions = listOf("int", "fr", "be")

    private fun generateRandomString(length: Int) = (1..length)
        .map { _ -> alphabet[Random.nextInt(0, alphabet.size)] }
        .joinToString("")

    fun createBatchOfUniqueCodes(size: Int) = (1..size)
        .fold(listOf<CodeDto>()) { acc, _ ->
            val lang = languages[Random.nextInt(0, languages.size)]
            val type = types[Random.nextInt(0, types.size)]
            val code = generateRandomString(20)
            val version = Random.nextInt(0, 10).toString()
            acc + CodeDto(
                id = "$type|$code|$version",
                type = type,
                code = code,
                version = version,
                label = if (Random.nextInt(0, 4) == 0) mapOf(lang to generateRandomString(Random.nextInt(20, 100))) else mapOf(),
                regions = if (Random.nextInt(0, 4) == 0) listOf(regions[Random.nextInt(0, regions.size)]) else listOf(),
                qualifiedLinks = if (Random.nextInt(0, 4) == 0) mapOf(generateRandomString(10) to List(
                    Random.nextInt(
                        1,
                        4
                    )
                ) { generateRandomString(10) }) else mapOf(),
                searchTerms = if (Random.nextInt(0, 4) == 0) mapOf(generateRandomString(10) to List(
                    Random.nextInt(
                        1,
                        4
                    )
                ) { generateRandomString(10) }.toSet()) else mapOf(),
            )
        }
}