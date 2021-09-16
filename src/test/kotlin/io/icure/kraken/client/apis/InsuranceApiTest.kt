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

import io.icure.kraken.client.models.DocIdentifier
import io.icure.kraken.client.models.InsuranceDto
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
 * API tests for InsuranceApi
 */
@ExperimentalStdlibApi
class InsuranceApiTest() {

    companion object {
        private val alreadyCreatedObjects = mutableSetOf<String>()
        fun canCreateForModificationObjects(fileName: String) = alreadyCreatedObjects.add(fileName)

        @JvmStatic
        fun fileNames() = listOf("InsuranceApi.json")
    }

    fun api(fileName: String) = InsuranceApi(basePath = "http://127.0.0.1:16043", authHeader = fileName.basicAuth())
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
                            InsuranceDto::class.java -> it to objectMapper.convertValue(body, InsuranceDto::class.java)
                            InsuranceApi::class.java -> it to api(credentialsFile)
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
     * Creates an insurance
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun createInsuranceTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "createInsurance")) {
                assert(true)
                println("Endpoint createInsurance skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "createInsurance")
                val insuranceDto: InsuranceDto = TestUtils.getParameter<InsuranceDto>(fileName, "createInsurance.insuranceDto")!!.let {
                    (it as? InsuranceDto)?.takeIf { TestUtils.isAutoRev(fileName, "createInsurance") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getInsurance(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? InsuranceDto ?: it
                    }

                val response = api(credentialsFile).createInsurance(insuranceDto)

                    val testFileName = "InsuranceApi.createInsurance"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<InsuranceDto>? != null) {
                            if ("InsuranceDto".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<InsuranceDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<InsuranceDto>() {}
                        })
                        assertAreEquals("createInsurance", objectFromFile, response)
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
            TestUtils.deleteAfterElements(fileName)
            alreadyCreatedObjects.remove(fileName)
        }
    }
    
    /**
     * Deletes an insurance
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun deleteInsuranceTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "deleteInsurance")) {
                assert(true)
                println("Endpoint deleteInsurance skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "deleteInsurance")
                val insuranceId: kotlin.String = TestUtils.getParameter<kotlin.String>(fileName, "deleteInsurance.insuranceId")!!.let {
                    (it as? InsuranceDto)?.takeIf { TestUtils.isAutoRev(fileName, "deleteInsurance") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getInsurance(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? kotlin.String ?: it
                    }

                val response = api(credentialsFile).deleteInsurance(insuranceId)

                    val testFileName = "InsuranceApi.deleteInsurance"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<DocIdentifier>? != null) {
                            if ("DocIdentifier".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<DocIdentifier>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<DocIdentifier>() {}
                        })
                        assertAreEquals("deleteInsurance", objectFromFile, response)
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
            TestUtils.deleteAfterElements(fileName)
            alreadyCreatedObjects.remove(fileName)
        }
    }
    
    /**
     * Gets an insurance
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun getInsuranceTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "getInsurance")) {
                assert(true)
                println("Endpoint getInsurance skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "getInsurance")
                val insuranceId: kotlin.String = TestUtils.getParameter<kotlin.String>(fileName, "getInsurance.insuranceId")!!.let {
                    (it as? InsuranceDto)?.takeIf { TestUtils.isAutoRev(fileName, "getInsurance") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getInsurance(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? kotlin.String ?: it
                    }

                val response = api(credentialsFile).getInsurance(insuranceId)

                    val testFileName = "InsuranceApi.getInsurance"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<InsuranceDto>? != null) {
                            if ("InsuranceDto".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<InsuranceDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<InsuranceDto>() {}
                        })
                        assertAreEquals("getInsurance", objectFromFile, response)
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
            TestUtils.deleteAfterElements(fileName)
            alreadyCreatedObjects.remove(fileName)
        }
    }
    
    /**
     * Gets insurances by id
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun getInsurancesTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "getInsurances")) {
                assert(true)
                println("Endpoint getInsurances skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "getInsurances")
                val listOfIdsDto: ListOfIdsDto = TestUtils.getParameter<ListOfIdsDto>(fileName, "getInsurances.listOfIdsDto")!!.let {
                    (it as? InsuranceDto)?.takeIf { TestUtils.isAutoRev(fileName, "getInsurances") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getInsurance(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? ListOfIdsDto ?: it
                    }

                val response = api(credentialsFile).getInsurances(listOfIdsDto)

                    val testFileName = "InsuranceApi.getInsurances"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<InsuranceDto>? != null) {
                            if ("kotlin.collections.List<InsuranceDto>".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<InsuranceDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<kotlin.collections.List<InsuranceDto>>() {}
                        })
                        assertAreEquals("getInsurances", objectFromFile, response)
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
            TestUtils.deleteAfterElements(fileName)
            alreadyCreatedObjects.remove(fileName)
        }
    }
    
    /**
     * Gets an insurance
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun listInsurancesByCodeTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "listInsurancesByCode")) {
                assert(true)
                println("Endpoint listInsurancesByCode skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "listInsurancesByCode")
                val insuranceCode: kotlin.String = TestUtils.getParameter<kotlin.String>(fileName, "listInsurancesByCode.insuranceCode")!!.let {
                    (it as? InsuranceDto)?.takeIf { TestUtils.isAutoRev(fileName, "listInsurancesByCode") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getInsurance(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? kotlin.String ?: it
                    }

                val response = api(credentialsFile).listInsurancesByCode(insuranceCode)

                    val testFileName = "InsuranceApi.listInsurancesByCode"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<InsuranceDto>? != null) {
                            if ("kotlin.collections.List<InsuranceDto>".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<InsuranceDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<kotlin.collections.List<InsuranceDto>>() {}
                        })
                        assertAreEquals("listInsurancesByCode", objectFromFile, response)
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
            TestUtils.deleteAfterElements(fileName)
            alreadyCreatedObjects.remove(fileName)
        }
    }
    
    /**
     * Gets an insurance
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun listInsurancesByNameTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "listInsurancesByName")) {
                assert(true)
                println("Endpoint listInsurancesByName skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "listInsurancesByName")
                val insuranceName: kotlin.String = TestUtils.getParameter<kotlin.String>(fileName, "listInsurancesByName.insuranceName")!!.let {
                    (it as? InsuranceDto)?.takeIf { TestUtils.isAutoRev(fileName, "listInsurancesByName") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getInsurance(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? kotlin.String ?: it
                    }

                val response = api(credentialsFile).listInsurancesByName(insuranceName)

                    val testFileName = "InsuranceApi.listInsurancesByName"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<InsuranceDto>? != null) {
                            if ("kotlin.collections.List<InsuranceDto>".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<InsuranceDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<kotlin.collections.List<InsuranceDto>>() {}
                        })
                        assertAreEquals("listInsurancesByName", objectFromFile, response)
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
            TestUtils.deleteAfterElements(fileName)
            alreadyCreatedObjects.remove(fileName)
        }
    }
    
    /**
     * Modifies an insurance
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun modifyInsuranceTest(fileName: String) = runBlocking {
        try{
            createForModification(fileName)
            if (TestUtils.skipEndpoint(fileName, "modifyInsurance")) {
                assert(true)
                println("Endpoint modifyInsurance skipped")
            } else {
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "modifyInsurance")
                val insuranceDto: InsuranceDto = TestUtils.getParameter<InsuranceDto>(fileName, "modifyInsurance.insuranceDto")!!.let {
                    (it as? InsuranceDto)?.takeIf { TestUtils.isAutoRev(fileName, "modifyInsurance") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getInsurance(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? InsuranceDto ?: it
                    }

                val response = api(credentialsFile).modifyInsurance(insuranceDto)

                    val testFileName = "InsuranceApi.modifyInsurance"
                    val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                    try {
                        val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<InsuranceDto>? != null) {
                            if ("InsuranceDto".contains("String>")) {
                                object : TypeReference<List<String>>() {}
                            } else {
                                object : TypeReference<List<InsuranceDto>>() {}
                            }
                        } else if(response as? kotlin.collections.Map<String, String>? != null){
                            object : TypeReference<Map<String,String>>() {}
                        } else {
                            object : TypeReference<InsuranceDto>() {}
                        })
                        assertAreEquals("modifyInsurance", objectFromFile, response)
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
            TestUtils.deleteAfterElements(fileName)
            alreadyCreatedObjects.remove(fileName)
        }
    }
    

    private suspend fun assertAreEquals(functionName: String, objectFromFile: Any?, response: Any) {
        when {
            objectFromFile as? Iterable<Any> != null -> {
                val toSkip : kotlin.collections.List<String> = when {
                    functionName.let { name -> listOf("create", "new").any { name.startsWith(it) } } -> listOf("id", "rev")
                    functionName.let { name -> listOf("modify", "set", "delete", "list").any { name.startsWith(it) } } -> listOf("rev")
                    else -> emptyList()
                }

                val diffs = objectFromFile
                    .takeUnless { (it as ArrayList<Any>).size != (response as ArrayList<Any>).size }
                    ?.let { objectFromFile
                        .zip(response as Iterable<Any>)
                        .map { pair -> filterDiffs(pair.first, pair.second, pair.first.differences(pair.second), toSkip) }
                        .flatten()
                        .toList()
                    }
                    ?: listOf(Diff("Lists are of different sizes ${(objectFromFile as ArrayList<Any>).size} <-> ${(response as ArrayList<Any>).size}", PropertyType.ListItem, listOf(), objectFromFile, response))

                assertTrue(diffs.isEmpty())
            }
            objectFromFile as? Flow<ByteBuffer> != null -> {
                objectFromFile.fold(ByteBuffer.allocate(0)) { acc, bb ->
                    ByteBuffer.allocate(bb.limit() + acc.limit()).apply { this.put(acc); this.put(bb) }
                }.let { buf -> ByteArray(buf.remaining()).also { buf.get(it) }}.contentEquals(
                    (response as Flow<ByteBuffer>).fold(ByteBuffer.allocate(0)) { acc, bb ->
                        ByteBuffer.allocate(bb.limit() + acc.limit()).apply { this.put(acc); this.put(bb) }
                    }.let { buf -> ByteArray(buf.remaining()).also { buf.get(it) }}
                )
            }
            else -> {
                val toSkip : kotlin.collections.List<String> = when {
                    functionName.let { name -> listOf("create").any { name.startsWith(it) } } -> listOf("id", "rev", "created", "modified")
                    functionName.let { name -> listOf("set",  "modify").any { name.startsWith(it) } } -> listOf("rev")
                    else -> emptyList()
                }
                val diffs = filterDiffs(objectFromFile, response, response.differences(objectFromFile), toSkip)
                assertTrue(diffs.isEmpty())
            }
        }
    }
}
