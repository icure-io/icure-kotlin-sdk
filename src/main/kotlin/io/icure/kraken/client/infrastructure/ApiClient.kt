package io.icure.kraken.client.infrastructure

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.json.JsonReadFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import io.icure.asyncjacksonhttpclient.net.params


import io.icure.asyncjacksonhttpclient.net.web.HttpMethod
import io.icure.asyncjacksonhttpclient.net.web.WebClient
import io.icure.asyncjacksonhttpclient.parser.toObject
import kotlinx.coroutines.ExperimentalCoroutinesApi

import java.io.File
import java.net.URI
import java.net.URLConnection
import java.time.Duration
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.OffsetDateTime
import java.time.OffsetTime
import java.util.Date

@ExperimentalStdlibApi
@ExperimentalCoroutinesApi
open class ApiClient(val baseUrl: String, val httpClient: WebClient) {
    companion object {
        protected const val ContentType = "Content-Type"
        protected const val Accept = "Accept"
        protected const val Authorization = "Authorization"
        protected const val JsonMediaType = "application/json"
        protected const val FormDataMediaType = "multipart/form-data"
        protected const val FormUrlEncMediaType = "application/x-www-form-urlencoded"
        protected const val XmlMediaType = "application/xml"

        val apiKey: MutableMap<String, String> = mutableMapOf()
        val apiKeyPrefix: MutableMap<String, String> = mutableMapOf()
        var username: String? = null
        var password: String? = null
        var accessToken: String? = null
 		var authHeader: String? = null
        var timeoutDuration: Duration? = null

        val objectMapper = ObjectMapper().registerModule(KotlinModule()).apply {
            setSerializationInclusion(JsonInclude.Include.NON_NULL)
            configure(JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS.mappedFeature(), true)
        }

    }

    /**
     * Guess Content-Type header from the given file (defaults to "application/octet-stream").
     *
     * @param file The given file
     * @return The guessed Content-Type
     */
    protected fun guessContentTypeFromFile(file: File): String {
        val contentType = URLConnection.guessContentTypeFromName(file.name)
        return contentType ?: "application/octet-stream"
    }

    protected inline suspend fun <reified I, reified T : Any?> request(requestConfig: RequestConfig<I>): T? {

        val uri = URI(baseUrl).params(
            requestConfig.query.mapValues(defaultMultiValueConverter)
        )

        // take authMethod from operation
        authHeader?.let { requestConfig.headers[Authorization] = it }

        // take content-type/accept from spec or set to default (application/json) if not defined
        if (requestConfig.headers[ContentType].isNullOrEmpty()) {
            requestConfig.headers[ContentType] = JsonMediaType
        }
        if (requestConfig.headers[Accept].isNullOrEmpty()) {
            requestConfig.headers[Accept] = JsonMediaType
        }

        var request = when (requestConfig.method) {
            RequestMethod.DELETE -> httpClient.uri(uri).method(HttpMethod.DELETE, timeoutDuration)
            RequestMethod.GET -> httpClient.uri(uri).method(HttpMethod.GET, timeoutDuration)
            RequestMethod.HEAD -> httpClient.uri(uri).method(HttpMethod.HEAD, timeoutDuration)
            RequestMethod.PATCH -> httpClient.uri(uri).method(HttpMethod.PATCH, timeoutDuration)
            RequestMethod.PUT -> httpClient.uri(uri).method(HttpMethod.PUT, timeoutDuration)
            RequestMethod.POST -> httpClient.uri(uri).method(HttpMethod.POST, timeoutDuration)
                .body(objectMapper.writeValueAsString(requestConfig.body))
            RequestMethod.OPTIONS -> httpClient.uri(uri).method(HttpMethod.OPTIONS, timeoutDuration)
        }.apply {
            requestConfig.headers.forEach { header -> header(header.key, header.value) }
        }

        username?.let {
            password?.let {
                request = request.basicAuth(username!!, password!!)
            }
        }

        return request.retrieve().toFlow().toObject(T::class.java, objectMapper, true)

    }

    protected inline fun <reified T: Any> parseDateToQueryString(value : T): String {
        /*
        .replace("\"", "") converts the json object string to an actual string for the query parameter.
        The moshi or gson adapter allows a more generic solution instead of trying to use a native
        formatter. It also easily allows to provide a simple way to define a custom date format pattern
        inside a gson/moshi adapter.
        */
        return objectMapper.writeValueAsString(value).replace("\"", "")
    }
}
