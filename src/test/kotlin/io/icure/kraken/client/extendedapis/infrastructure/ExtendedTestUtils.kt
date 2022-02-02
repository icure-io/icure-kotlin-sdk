package io.icure.kraken.client.extendedapis.infrastructure

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.readValue
import io.icure.kraken.client.infrastructure.TestUtils
import io.icure.kraken.client.infrastructure.TestUtils.Companion.toByteArraySafe
import io.icure.kraken.client.infrastructure.UsernamePassword
import kotlinx.coroutines.reactive.awaitFirstOrNull
import reactor.core.publisher.Mono
import reactor.netty.http.client.HttpClient
import java.io.File
import java.net.URI
import java.net.URLEncoder

object ExtendedTestUtils {

    suspend fun deleteElements(documentFamily: String, documentIds: List<String>) {
        val usernamePassword: UsernamePassword = TestUtils.objectMapper.readValue(File(".credentialsCouchDb").readText())!!
        val u = usernamePassword.username
        val p = usernamePassword.password

        val httpClient = HttpClient.create().headers { h ->
            h.set("Authorization", UsernamePassword(u,p).toBasicAuth())
            h.set("Content-type", "application/json")
        }

        documentIds.forEach { id ->
            val res = httpClient.get()
                .uri(URI("https://couch.svcacc.icure.cloud/icure-test-2-tz-dev-team-$documentFamily/${URLEncoder.encode(id, Charsets.UTF_8)}"))
                .responseSingle{ response, bytes ->
                    if (response.status().code()<400) {
                        bytes.mapNotNull { TestUtils.objectMapper.readValue(it.toByteArraySafe(), object:
                            TypeReference<IdWithRev>() {}) }
                            .flatMap {
                                it?.let {
                                    httpClient.delete()
                                        .uri(URI("https://couch.svcacc.icure.cloud/icure-test-2-tz-dev-team-$documentFamily/${URLEncoder.encode(id, Charsets.UTF_8)}?rev=${URLEncoder.encode(it.rev, Charsets.UTF_8)}")).response()
                                } ?: Mono.empty()
                            }
                    } else Mono.empty()
                }.awaitFirstOrNull()
            TestUtils.log.info {"Delete : $id <- ${res?.status()?.code()}"}
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class IdWithRev(@field:JsonProperty("_id") val id: String, @field:JsonProperty("_rev") val rev: String)
}