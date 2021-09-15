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

package io.icure.kraken.client.apis

import io.icure.kraken.client.models.ArticleDto
import io.icure.kraken.client.models.DocIdentifier
import io.icure.kraken.client.models.ListOfIdsDto
import assertk.assertThat
import assertk.assertions.isEqualToIgnoringGivenProperties
import java.io.*

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.json.JsonReadFeature
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import io.icure.kraken.client.infrastructure.*

import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.reflect.KProperty1
import kotlin.reflect.KMutableProperty
import kotlin.reflect.full.memberFunctions
import kotlin.reflect.full.memberProperties

import kotlinx.coroutines.runBlocking
import io.icure.kraken.client.infrastructure.TestUtils
import io.icure.kraken.client.infrastructure.TestUtils.Companion.basicAuth
import io.icure.kraken.client.infrastructure.differences
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.fold
import java.nio.ByteBuffer
import kotlin.reflect.full.callSuspendBy
import kotlin.reflect.javaType
import kotlinx.coroutines.flow.flow

/**
 * API tests for ArticleApi
 */
@ExperimentalStdlibApi
class ArticleApiTest() {

    companion object {
        private val alreadyCreatedObjects = mutableSetOf<String>()
        fun canCreateForModificationObjects(fileName: String) = alreadyCreatedObjects.add(fileName)

        @JvmStatic
        @AfterAll
        fun afterAllTests(){
        TestUtils.deleteAfterElements("ArticleApi.json")
        }

        @JvmStatic
        fun fileNames() = listOf("ArticleApi.json")
    }

    fun api(fileName: String) = ArticleApi(basePath = "http://127.0.0.1:16043", authHeader = fileName.basicAuth())
    private val workingFolder = "/tmp/icureTests/"
    private val objectMapper = ObjectMapper()
        .registerModule(KotlinModule())
        .registerModule(object:SimpleModule() {
            override fun setupModule(context: SetupContext?) {
                super.setupModule(context)
                addDeserializer(ByteArrayWrapper::class.java, ByteArrayWrapperDeserializer())
                addSerializer(ByteArrayWrapper::class.java, ByteArrayWrapperSerializer())
            }
        })
        .registerModule(JavaTimeModule())
        .apply {
        setSerializationInclusion(JsonInclude.Include.NON_NULL)
        configure(JsonReadFeature.ALLOW_UNESCAPED_CONTROL_CHARS.mappedFeature(), true)
        configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true)
    }

    suspend fun createForModification(fileName: String){
        if (canCreateForModificationObjects(fileName)) {
            TestUtils.getParameters<Any>(fileName, "beforeElements.bodies")?.let {bodies ->
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "createDto")
                val createFunction = api(credentialsFile)::class.memberFunctions
                    .firstOrNull { it.parameters.size == 3; it.name.startsWith("create") }
                val deleteFunction = api(credentialsFile)::class.memberFunctions
                    .firstOrNull { it.parameters.size == 3 && it.name.startsWith("delete") }
                bodies.forEach {body ->
                    //deleteFunction?.call(api, body?.id)
                    val parameters = createFunction!!.parameters.mapNotNull {
                        when(it.type.javaType) {
                            ArticleDto::class.java -> it to objectMapper.convertValue(body, ArticleDto::class.java)
                            ArticleApi::class.java -> it to api(credentialsFile)
                            else -> null
                        }
                    }.toMap()


                    createFunction.callSuspendBy(parameters)
                    println("created")
                }
            }
        }
    }

    
    /**
     * Creates a article
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun createArticleTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "createArticle")) {
                assert(true)
                println("Endpoint createArticle skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "createArticle")
                val articleDto: ArticleDto = TestUtils.getParameter(fileName, "createArticle.articleDto")!!
                    if (articleDto as? Collection<*> == null) {
                        articleDto.also {
                    if (TestUtils.isAutoRev(fileName, "createArticle") && it != null) {
                        val id = it::class.memberProperties.first { it.name == "id" }
                        val currentRev = api(credentialsFile).getArticle(id.getter.call(it) as String).rev
                        val rev = object: TypeReference<ArticleDto>(){}.type::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                        rev.setter.call(it, currentRev)
                    }
                }
                } else {
                    val paramAsCollection = articleDto as? Collection<ArticleDto> ?: emptyList<ArticleDto>() as Collection<ArticleDto>
                    paramAsCollection.forEach {
                        if (TestUtils.isAutoRev(fileName, "createArticle") && it != null) {
                            val id = it::class.memberProperties.first { it.name == "id" }

                            val currentRev = api(credentialsFile).getArticle(id.getter.call(it) as String).rev
                            val rev = it::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                            rev.setter.call(it, currentRev)
                        }
                    }
                }

                val response = api(credentialsFile).createArticle(articleDto)

                    val testFileName = "ArticleApi.createArticle"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ArticleDto>? != null) {
                            if ("ArticleDto".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<ArticleDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<ArticleDto>() {}
                        })
                        assertAreEquals("createArticle", objectFromFile, response)
                        println("Comparison successful")
                    }
                    catch (e: Exception) {
                        when (e) {
                            is FileNotFoundException, is java.nio.file.NoSuchFileException -> {
                                file.parentFile.mkdirs()
                                file.createNewFile()
                                (response as? Flow<ByteBuffer>)
                                    ?.let { it.writeToFile(file) }
                                    ?: objectMapper.writeValue(file, response)
                                assert(true)
                                println("File written")
                            }
                        }
                    }
            }
        }
        finally {
            TestUtils.deleteAfterElements("ArticleApi.json")
        }
    }
    
    /**
     * Deletes articles
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun deleteArticlesTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "deleteArticles")) {
                assert(true)
                println("Endpoint deleteArticles skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "deleteArticles")
                val listOfIdsDto: ListOfIdsDto = TestUtils.getParameter(fileName, "deleteArticles.listOfIdsDto")!!
                    if (listOfIdsDto as? Collection<*> == null) {
                        listOfIdsDto.also {
                    if (TestUtils.isAutoRev(fileName, "deleteArticles") && it != null) {
                        val id = it::class.memberProperties.first { it.name == "id" }
                        val currentRev = api(credentialsFile).getArticle(id.getter.call(it) as String).rev
                        val rev = object: TypeReference<ListOfIdsDto>(){}.type::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                        rev.setter.call(it, currentRev)
                    }
                }
                } else {
                    val paramAsCollection = listOfIdsDto as? Collection<ListOfIdsDto> ?: emptyList<ListOfIdsDto>() as Collection<ListOfIdsDto>
                    paramAsCollection.forEach {
                        if (TestUtils.isAutoRev(fileName, "deleteArticles") && it != null) {
                            val id = it::class.memberProperties.first { it.name == "id" }

                            val currentRev = api(credentialsFile).getArticle(id.getter.call(it) as String).rev
                            val rev = it::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                            rev.setter.call(it, currentRev)
                        }
                    }
                }

                val response = api(credentialsFile).deleteArticles(listOfIdsDto)

                    val testFileName = "ArticleApi.deleteArticles"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<DocIdentifier>? != null) {
                            if ("kotlin.collections.List<DocIdentifier>".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<DocIdentifier>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<kotlin.collections.List<DocIdentifier>>() {}
                        })
                        assertAreEquals("deleteArticles", objectFromFile, response)
                        println("Comparison successful")
                    }
                    catch (e: Exception) {
                        when (e) {
                            is FileNotFoundException, is java.nio.file.NoSuchFileException -> {
                                file.parentFile.mkdirs()
                                file.createNewFile()
                                (response as? Flow<ByteBuffer>)
                                    ?.let { it.writeToFile(file) }
                                    ?: objectMapper.writeValue(file, response)
                                assert(true)
                                println("File written")
                            }
                        }
                    }
            }
        }
        finally {
            TestUtils.deleteAfterElements("ArticleApi.json")
        }
    }
    
    /**
     * Gets an article
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun getArticleTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "getArticle")) {
                assert(true)
                println("Endpoint getArticle skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "getArticle")
                val articleId: kotlin.String = TestUtils.getParameter(fileName, "getArticle.articleId")!!
                    if (articleId as? Collection<*> == null) {
                        articleId.also {
                    if (TestUtils.isAutoRev(fileName, "getArticle") && it != null) {
                        val id = it::class.memberProperties.first { it.name == "id" }
                        val currentRev = api(credentialsFile).getArticle(id.getter.call(it) as String).rev
                        val rev = object: TypeReference<kotlin.String>(){}.type::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                        rev.setter.call(it, currentRev)
                    }
                }
                } else {
                    val paramAsCollection = articleId as? Collection<kotlin.String> ?: emptyList<kotlin.String>() as Collection<kotlin.String>
                    paramAsCollection.forEach {
                        if (TestUtils.isAutoRev(fileName, "getArticle") && it != null) {
                            val id = it::class.memberProperties.first { it.name == "id" }

                            val currentRev = api(credentialsFile).getArticle(id.getter.call(it) as String).rev
                            val rev = it::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                            rev.setter.call(it, currentRev)
                        }
                    }
                }

                val response = api(credentialsFile).getArticle(articleId)

                    val testFileName = "ArticleApi.getArticle"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ArticleDto>? != null) {
                            if ("ArticleDto".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<ArticleDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<ArticleDto>() {}
                        })
                        assertAreEquals("getArticle", objectFromFile, response)
                        println("Comparison successful")
                    }
                    catch (e: Exception) {
                        when (e) {
                            is FileNotFoundException, is java.nio.file.NoSuchFileException -> {
                                file.parentFile.mkdirs()
                                file.createNewFile()
                                (response as? Flow<ByteBuffer>)
                                    ?.let { it.writeToFile(file) }
                                    ?: objectMapper.writeValue(file, response)
                                assert(true)
                                println("File written")
                            }
                        }
                    }
            }
        }
        finally {
            TestUtils.deleteAfterElements("ArticleApi.json")
        }
    }
    
    /**
     * Gets all articles
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun getArticlesTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "getArticles")) {
                assert(true)
                println("Endpoint getArticles skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "getArticles")

                val response = api(credentialsFile).getArticles()

                    val testFileName = "ArticleApi.getArticles"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ArticleDto>? != null) {
                            if ("kotlin.collections.List<ArticleDto>".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<ArticleDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<kotlin.collections.List<ArticleDto>>() {}
                        })
                        assertAreEquals("getArticles", objectFromFile, response)
                        println("Comparison successful")
                    }
                    catch (e: Exception) {
                        when (e) {
                            is FileNotFoundException, is java.nio.file.NoSuchFileException -> {
                                file.parentFile.mkdirs()
                                file.createNewFile()
                                (response as? Flow<ByteBuffer>)
                                    ?.let { it.writeToFile(file) }
                                    ?: objectMapper.writeValue(file, response)
                                assert(true)
                                println("File written")
                            }
                        }
                    }
            }
        }
        finally {
            TestUtils.deleteAfterElements("ArticleApi.json")
        }
    }
    
    /**
     * Modifies an article
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun modifyArticleTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "modifyArticle")) {
                assert(true)
                println("Endpoint modifyArticle skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "modifyArticle")
                val articleDto: ArticleDto = TestUtils.getParameter(fileName, "modifyArticle.articleDto")!!
                    if (articleDto as? Collection<*> == null) {
                        articleDto.also {
                    if (TestUtils.isAutoRev(fileName, "modifyArticle") && it != null) {
                        val id = it::class.memberProperties.first { it.name == "id" }
                        val currentRev = api(credentialsFile).getArticle(id.getter.call(it) as String).rev
                        val rev = object: TypeReference<ArticleDto>(){}.type::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                        rev.setter.call(it, currentRev)
                    }
                }
                } else {
                    val paramAsCollection = articleDto as? Collection<ArticleDto> ?: emptyList<ArticleDto>() as Collection<ArticleDto>
                    paramAsCollection.forEach {
                        if (TestUtils.isAutoRev(fileName, "modifyArticle") && it != null) {
                            val id = it::class.memberProperties.first { it.name == "id" }

                            val currentRev = api(credentialsFile).getArticle(id.getter.call(it) as String).rev
                            val rev = it::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                            rev.setter.call(it, currentRev)
                        }
                    }
                }

                val response = api(credentialsFile).modifyArticle(articleDto)

                    val testFileName = "ArticleApi.modifyArticle"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ArticleDto>? != null) {
                            if ("ArticleDto".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<ArticleDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<ArticleDto>() {}
                        })
                        assertAreEquals("modifyArticle", objectFromFile, response)
                        println("Comparison successful")
                    }
                    catch (e: Exception) {
                        when (e) {
                            is FileNotFoundException, is java.nio.file.NoSuchFileException -> {
                                file.parentFile.mkdirs()
                                file.createNewFile()
                                (response as? Flow<ByteBuffer>)
                                    ?.let { it.writeToFile(file) }
                                    ?: objectMapper.writeValue(file, response)
                                assert(true)
                                println("File written")
                            }
                        }
                    }
            }
        }
        finally {
            TestUtils.deleteAfterElements("ArticleApi.json")
        }
    }
    

    private suspend fun assertAreEquals(functionName: String, objectFromFile: Any?, response: Any) {
        when {
            objectFromFile as? Iterable<Any> != null -> {
                val iterableResponse = (response as? Collection<Any> ?: (emptyList<Any>()))
                if (functionName.startsWith("create") || functionName.startsWith("new")) { // new
                    for (fileElement in objectFromFile) {
                        fileElement::class.memberProperties.filterIsInstance<KMutableProperty<*>>().firstOrNull { it.name == "id" }?.setter?.call(fileElement, null)
                        fileElement::class.memberProperties.filterIsInstance<KMutableProperty<*>>().firstOrNull { it.name == "rev" }?.setter?.call(fileElement, null)
                    }
                    for (responseElement in iterableResponse) {
                        responseElement::class.memberProperties.filterIsInstance<KMutableProperty<*>>().firstOrNull { it.name == "id" }?.setter?.call(responseElement, null)
                        responseElement::class.memberProperties.filterIsInstance<KMutableProperty<*>>().firstOrNull { it.name == "rev" }?.setter?.call(responseElement, null)
                    }
                } else if (functionName.startsWith("modify") || functionName.startsWith("set") || functionName.startsWith("delete")) { // + set + delete
                    for (fileElement in objectFromFile) {
                        fileElement::class.memberProperties.filterIsInstance<KMutableProperty<*>>().firstOrNull { it.name == "rev" }?.setter?.call(fileElement, null)
                    }
                    for (responseElement in iterableResponse) {
                        responseElement::class.memberProperties.filterIsInstance<KMutableProperty<*>>().firstOrNull { it.name == "rev" }?.setter?.call(responseElement, null)
                    }
                }
                val diffs = response.differences(objectFromFile)
                assertTrue(diffs.isEmpty())
            }
            objectFromFile as? Flow<ByteBuffer> != null -> {
                objectFromFile.fold(ByteBuffer.allocate(0)) { acc, bb -> ByteBuffer.allocate(bb.limit()+acc.limit()).apply { this.put(acc); this.put(bb) } }.array().contentEquals(
                    (response as Flow<ByteBuffer>).fold(ByteBuffer.allocate(0)) { acc, bb -> ByteBuffer.allocate(bb.limit()+acc.limit()).apply { this.put(acc); this.put(bb) } }.array()
                )
            }
            else -> {
                if (functionName.startsWith("create") || functionName.startsWith("modify")) {
                    assertThat(objectFromFile as Any).isEqualToIgnoringGivenProperties(response, *(response::class.memberProperties.filter { it.name == "rev" || it.name == "id" || it.name == "created"  || it.name == "modified" }.mapNotNull { it as? KProperty1<Any, Any> }.toTypedArray()))
                } else {
                    assertEquals(objectFromFile, response)
                }
            }
        }
    }

}
