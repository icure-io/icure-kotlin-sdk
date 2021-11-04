/**
 * iCure Data Stack API Documentation
 *
 * The iCure Data Stack Application API is the native interface to iCure.
 *
 * The version of the OpenAPI document: v2
 *
 *
 * Please note:
 * This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * Do not edit this file manually.
 */

package io.icure.kraken.client.infrastructure

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.core.json.JsonReadFeature
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.readValue
import io.icure.kraken.client.models.IdWithRevDto
import io.icure.kraken.client.models.decrypted.IcureStubDto
import io.icure.kraken.client.models.filter.AbstractFilterDto
import io.netty.buffer.ByteBuf
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.reactive.awaitFirst
import kotlinx.coroutines.reactive.awaitFirstOrNull
import org.junit.platform.commons.logging.LoggerFactory
import reactor.core.publisher.Mono
import reactor.netty.http.client.HttpClient
import java.io.File
import java.io.IOException
import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import java.util.concurrent.TimeUnit
import java.util.function.BiFunction
import kotlin.system.exitProcess


class TestUtils {
    companion object {
        val log = LoggerFactory.getLogger(this.javaClass)
        val objectMapper = ObjectMapper()
            .registerModule(KotlinModule())
            .registerModule(object:SimpleModule() {
                override fun setupModule(context: SetupContext?) {
                    addDeserializer(ByteArrayWrapper::class.java, ByteArrayWrapperDeserializer())
                    addSerializer(ByteArrayWrapper::class.java, ByteArrayWrapperSerializer())
                    addDeserializer(AbstractFilterDto::class.java, FilterDeserializer())
                    super.setupModule(context)
                }
            })
            .registerModule(JavaTimeModule()).apply {
                setSerializationInclusion(JsonInclude.Include.NON_NULL)
                configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true)
                configure(JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS.mappedFeature(), true)
            }

        val globalParams: Map<String, Any> = objectMapper.readValue(this::class.java.classLoader.getResource("parameters/Global.json").readText(),
            object: TypeReference<Map<String, Any>>() {})

        inline fun <reified T> getParameter(fileName: String, name: String): T? {
            val paramElements = name.split(".")
            val localParams = objectMapper.readValue(this::class.java.classLoader.getResource("parameters/$fileName").readText(),
                object: TypeReference<Map<String, Any>>() {})

            return localParams?.let {
                val methodParams: Map<String, Any>? = localParams[paramElements[0]] as Map<String, Any>?
                methodParams?.let {
                    when(T::class){
                        Long::class -> (methodParams[paramElements[1]] as? Long?)?.toLong() as T? ?:(methodParams[paramElements[1]] as? Int?)?.toLong() as T? ?: (getGlobalParam(paramElements[1]) as Long?)?.toLong() as T?
                        Flow::class -> flowOf(methodParams[paramElements[1]]) as T?
                        else -> objectMapper.readValue(objectMapper.writeValueAsString(methodParams[paramElements[1]])) ?: getGlobalObjectParam(
                            paramElements[1]
                        )
                    }
                }
            }
        }

        inline fun <reified T> getParameters(fileName: String, name: String): kotlin.collections.List<T?>? {
            val paramElements = name.split(".")
            val localParams: Map<String, Any> =
                objectMapper.readValue(this::class.java.classLoader.getResource("parameters/$fileName").readText())

            return localParams.let {
                val methodParams: Map<String, List<*>>? = localParams[paramElements[0]] as Map<String, List<*>>?
                methodParams?.let {
                    methodParams[paramElements[1]]
                        ?.map { objectMapper.readValue(objectMapper.writeValueAsString(it), T::class.java) }
                        ?.toList()
                }
            }
        }

        inline fun <reified T> getGlobalObjectParam(globalParam: String): T?{
            for ((k, v) in globalParams) {
                if (globalParam.endsWith(k)) {
                    return objectMapper.readValue(objectMapper.writeValueAsString(v))
                }
            }
            return null
        }

        inline fun getGlobalParam(globalParam: String): Any? {
            for ((k, v) in globalParams) {
                if (globalParam.endsWith(k)) {
                    return v
                }
            }
            return null
        }

        fun isAutoRev(parmatersFileName: String, callingFunctionName: String): Boolean {
            val isAutoRev  = getParameter<Boolean>(parmatersFileName, "$callingFunctionName.autoRev")
            return isAutoRev ?: false
        }

        fun skipEndpoint(parmatersFileName: String, callingFunctionName: String): Boolean {
            val skipEndpoint  = getParameter<Boolean>(parmatersFileName, "$callingFunctionName.skipEndpoint")
            return skipEndpoint ?: false
        }

        fun getCredentialsFile(parmatersFileName: String, callingFunctionName: String): String {
            val credentialsFileFromParametersFile  = getParameter<String>(parmatersFileName, "$callingFunctionName.credentialsFile")
            return credentialsFileFromParametersFile ?: infereCredentialsFile(callingFunctionName)
        }

        suspend fun deleteAfterElements(parametersFileName: String) {
            val callingFunctionName = "afterElements"
            val usernamePassword: UsernamePassword = Companion.objectMapper.readValue(File(".credentialsCouchDb").readText())!!
            val u = usernamePassword.username
            val p = usernamePassword.password
            val family  = getParameter<String>(parametersFileName, "$callingFunctionName.family")
            val ids  = getParameter<List<String>>(parametersFileName, "$callingFunctionName.deleteIds")
            val httpClient = HttpClient.create().headers { h ->
                h.set("Authorization", UsernamePassword(u,p).toBasicAuth())
                h.set("Content-type", "application/json")
            }

            if (family != null && ids != null) {
                ids.forEach { id ->
                    val res = httpClient.get()
                        .uri(URI("https://couch.svcacc.icure.cloud/icure-test-2-tz-dev-team-$family/$id"))
                        .responseSingle{ response, bytes ->
                            if (response.status().code()<400) {
                                bytes.mapNotNull { objectMapper?.readValue(it.toByteArraySafe(), object:TypeReference<IdWithRev>() {}) }
                                    .flatMap {
                                        it?.let { httpClient.delete().uri(URI("https://couch.svcacc.icure.cloud/icure-test-2-tz-dev-team-$family/$id?rev=${it.rev}")).response() } ?: Mono.empty()
                                    }
                            } else Mono.empty()
                        }.awaitFirstOrNull()
                    log.info {"Delete : $id <- ${res?.status()?.code()}"}
                }
            }
        }

        fun ByteBuf.toByteArraySafe(): ByteArray {
            if (this.hasArray()) {
                return this.array()
            }

            val bytes = ByteArray(this.readableBytes())
            this.getBytes(this.readerIndex(), bytes)

            return bytes
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        private data class IdWithRev(@field:JsonProperty("_id") val id: String, @field:JsonProperty("_rev") val rev: String)

        private fun infereCredentialsFile(callingFunctionName: String): String {
            return when {
                callingFunctionName.startsWith("new") -> {
                    ".credentialsReadWrite"
                }
                callingFunctionName.startsWith("delete") -> {
                    ".credentialsReadWrite"
                }
                callingFunctionName.startsWith("create") -> {
                    ".credentialsReadWrite"
                }
                callingFunctionName.startsWith("modify") -> {
                    ".credentialsReadWrite"
                }
                callingFunctionName.startsWith("set") -> {
                    ".credentialsReadWrite"
                }
                callingFunctionName.startsWith("undelete") -> {
                    ".credentialsReadWrite"
                }
                else -> {
                    ".credentialsReadOnly"
                }
            }
        }

        fun String.basicAuth() : String {
            val usernamePassword: UsernamePassword = objectMapper.readValue(File(this).readText())!!
            return usernamePassword.toBasicAuth()
        }

        fun String.runCommandExitStatus(path: String = ".", streamOutput: Boolean = true, checkReturnValue: Boolean = true, variables: Map<String, String> = mapOf(), suicideOnFailure: Boolean = false): Pair<String, Int> {
            val output = if (streamOutput) ProcessBuilder.Redirect.INHERIT else ProcessBuilder.Redirect.PIPE
            try {
                val workingDir = File(path)
                val parts = listOf("sh", "-c", this)
                val proc = ProcessBuilder(*parts.toTypedArray())
                    .directory(workingDir)
                    .redirectErrorStream(true)
                    .redirectOutput(output)
                    .also {
                        val env = it.environment()
                        variables.forEach { (name, value) ->
                            env[name] = value
                        }
                    }
                    .start()
                val result = proc.inputStream.bufferedReader().readText().trim()
                if (!proc.waitFor(60, TimeUnit.MINUTES)) throw UnsupportedOperationException("Failed executing command $this: waitFor returned false")
                if (checkReturnValue && proc.exitValue() != 0) println("Process exit value ${proc.exitValue()}, command was '$this', result was '$result'")
                if (suicideOnFailure && proc.exitValue() != 0) exitProcess(1)
                return Pair(result, proc.exitValue())
            } catch (e: IOException) {
                throw UnsupportedOperationException("Failed executing command $this: $e")
            }
        }

        fun String.runCommand(path: String = ".", streamOutput: Boolean = true, checkReturnValue: Boolean = true, variables: Map<String, String> = mapOf(), suicideOnFailure: Boolean = false) =
            runCommandExitStatus(path, streamOutput, checkReturnValue, variables, suicideOnFailure).first
    }
}

suspend fun Flow<ByteBuffer>.writeToFile(file:File) = FileChannel.open(file.toPath(), StandardOpenOption.WRITE).use { channel ->
    this@writeToFile.collect { b -> channel.write(b) }
}

/*fun Flow<ByteBuffer>.writeToFile(file:File) = file.bufferedWriter().use { writer ->
    CoroutineScope((Dispatchers.IO)).launch {
        this@writeToFile.collect {
            writer.write(it.asCharBuffer().array())
        }
    }
}*/

@Suppress("BlockingMethodInNonBlockingContext")
fun File.readAsFlow() = flow {
    FileChannel.open(this@readAsFlow.toPath()).use { channel ->
        do {
            val b = ByteBuffer.allocate(4096)
            val read = channel.read(b)
            if (read>0) { emit(b) }
        } while(read>0)
    }
}

data class UsernamePassword(val username: String, val password: String) {
    fun toBasicAuth() = "Basic ${java.util.Base64.getEncoder().encodeToString("$username:$password".toByteArray())}"
}
