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

import io.icure.kraken.client.models.ClassificationDto
import io.icure.kraken.client.models.DelegationDto
import io.icure.kraken.client.models.DocIdentifier
import io.icure.kraken.client.models.IcureStubDto
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
import io.icure.kraken.client.models.filter.AbstractFilterDto

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
import kotlinx.coroutines.flow.toList

/**
 * API tests for ClassificationApi
 */
@ExperimentalStdlibApi
class ClassificationApiTest() {

    companion object {
        private val alreadyCreatedObjects = mutableSetOf<String>()
        fun canCreateForModificationObjects(fileName: String) = alreadyCreatedObjects.add(fileName)

        @JvmStatic
        fun fileNames() = listOf("ClassificationApi.json")
    }

    // http://127.0.0.1:16043
    fun api(fileName: String) = ClassificationApi(basePath = java.lang.System.getProperty("API_URL"), authHeader = fileName.basicAuth())
    private val workingFolder = "/tmp/icureTests/"
    private val objectMapper = ObjectMapper()
        .registerModule(KotlinModule())
        .registerModule(object:SimpleModule() {
            override fun setupModule(context: SetupContext?) {
                addDeserializer(AbstractFilterDto::class.java, FilterDeserializer())
                addDeserializer(ByteArrayWrapper::class.java, ByteArrayWrapperDeserializer())
                addSerializer(ByteArrayWrapper::class.java, ByteArrayWrapperSerializer())
                super.setupModule(context)
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
                            ClassificationDto::class.java -> it to objectMapper.convertValue(body, ClassificationDto::class.java)
                            ClassificationApi::class.java -> it to api(credentialsFile)
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
     * Create a classification with the current user
     *
     * Returns an instance of created classification Template.
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun createClassificationTest(fileName: String) = runBlocking {

        if (TestUtils.skipEndpoint(fileName, "createClassification")) {
            assertTrue(true, "Test of createClassification endpoint has been skipped")
        } else {
            try{
                createForModification(fileName)
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "createClassification")
                val classificationDto: ClassificationDto = TestUtils.getParameter<ClassificationDto>(fileName, "createClassification.classificationDto")!!.let {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "createClassification") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? ClassificationDto ?: it
                    }

                val response = api(credentialsFile).createClassification(classificationDto = classificationDto)

                val testFileName = "ClassificationApi.createClassification"
                val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                try {
                    val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ClassificationDto>? != null) {
                        if ("ClassificationDto".contains("String>")) {
                            object : TypeReference<List<String>>() {}
                        } else {
                            object : TypeReference<List<ClassificationDto>>() {}
                        }
                    } else if(response as? kotlin.collections.Map<String, String>? != null){
                        object : TypeReference<Map<String,String>>() {}
                    } else {
                        object : TypeReference<ClassificationDto>() {}
                    })
                    assertAreEquals("createClassification", objectFromFile, response)
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
            finally {
                TestUtils.deleteAfterElements(fileName)
                alreadyCreatedObjects.remove(fileName)
            }
        }
    }
    
    /**
     * Delete classification Templates.
     *
     * Response is a set containing the ID&#39;s of deleted classification Templates.
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun deleteClassificationsTest(fileName: String) = runBlocking {

        if (TestUtils.skipEndpoint(fileName, "deleteClassifications")) {
            assertTrue(true, "Test of deleteClassifications endpoint has been skipped")
        } else {
            try{
                createForModification(fileName)
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "deleteClassifications")
                val listOfIdsDto: ListOfIdsDto = TestUtils.getParameter<ListOfIdsDto>(fileName, "deleteClassifications.listOfIdsDto")!!.let {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "deleteClassifications") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? ListOfIdsDto ?: it
                    }

                val response = api(credentialsFile).deleteClassifications(listOfIdsDto = listOfIdsDto)

                val testFileName = "ClassificationApi.deleteClassifications"
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
                    assertAreEquals("deleteClassifications", objectFromFile, response)
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
            finally {
                TestUtils.deleteAfterElements(fileName)
                alreadyCreatedObjects.remove(fileName)
            }
        }
    }
    
    /**
     * List classification Templates found By Healthcare Party and secret foreign keyelementIds.
     *
     * Keys hast to delimited by coma
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun findClassificationsByHCPartyPatientForeignKeysTest(fileName: String) = runBlocking {

        if (TestUtils.skipEndpoint(fileName, "findClassificationsByHCPartyPatientForeignKeys")) {
            assertTrue(true, "Test of findClassificationsByHCPartyPatientForeignKeys endpoint has been skipped")
        } else {
            try{
                createForModification(fileName)
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "findClassificationsByHCPartyPatientForeignKeys")
                val hcPartyId: kotlin.String = TestUtils.getParameter<kotlin.String>(fileName, "findClassificationsByHCPartyPatientForeignKeys.hcPartyId")!!.let {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "findClassificationsByHCPartyPatientForeignKeys") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? kotlin.String ?: it
                    }
                val secretFKeys: kotlin.String = TestUtils.getParameter<kotlin.String>(fileName, "findClassificationsByHCPartyPatientForeignKeys.secretFKeys")!!.let {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "findClassificationsByHCPartyPatientForeignKeys") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? kotlin.String ?: it
                    }

                val response = api(credentialsFile).findClassificationsByHCPartyPatientForeignKeys(hcPartyId = hcPartyId,secretFKeys = secretFKeys)

                val testFileName = "ClassificationApi.findClassificationsByHCPartyPatientForeignKeys"
                val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                try {
                    val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ClassificationDto>? != null) {
                        if ("kotlin.collections.List<ClassificationDto>".contains("String>")) {
                            object : TypeReference<List<String>>() {}
                        } else {
                            object : TypeReference<List<ClassificationDto>>() {}
                        }
                    } else if(response as? kotlin.collections.Map<String, String>? != null){
                        object : TypeReference<Map<String,String>>() {}
                    } else {
                        object : TypeReference<kotlin.collections.List<ClassificationDto>>() {}
                    })
                    assertAreEquals("findClassificationsByHCPartyPatientForeignKeys", objectFromFile, response)
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
            finally {
                TestUtils.deleteAfterElements(fileName)
                alreadyCreatedObjects.remove(fileName)
            }
        }
    }
    
    /**
     * Get a classification Template
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun getClassificationTest(fileName: String) = runBlocking {

        if (TestUtils.skipEndpoint(fileName, "getClassification")) {
            assertTrue(true, "Test of getClassification endpoint has been skipped")
        } else {
            try{
                createForModification(fileName)
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "getClassification")
                val classificationId: kotlin.String = TestUtils.getParameter<kotlin.String>(fileName, "getClassification.classificationId")!!.let {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "getClassification") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? kotlin.String ?: it
                    }

                val response = api(credentialsFile).getClassification(classificationId = classificationId)

                val testFileName = "ClassificationApi.getClassification"
                val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                try {
                    val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ClassificationDto>? != null) {
                        if ("ClassificationDto".contains("String>")) {
                            object : TypeReference<List<String>>() {}
                        } else {
                            object : TypeReference<List<ClassificationDto>>() {}
                        }
                    } else if(response as? kotlin.collections.Map<String, String>? != null){
                        object : TypeReference<Map<String,String>>() {}
                    } else {
                        object : TypeReference<ClassificationDto>() {}
                    })
                    assertAreEquals("getClassification", objectFromFile, response)
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
            finally {
                TestUtils.deleteAfterElements(fileName)
                alreadyCreatedObjects.remove(fileName)
            }
        }
    }
    
    /**
     * Get a list of classifications
     *
     * Ids are seperated by a coma
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun getClassificationByHcPartyIdTest(fileName: String) = runBlocking {

        if (TestUtils.skipEndpoint(fileName, "getClassificationByHcPartyId")) {
            assertTrue(true, "Test of getClassificationByHcPartyId endpoint has been skipped")
        } else {
            try{
                createForModification(fileName)
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "getClassificationByHcPartyId")
                val ids: kotlin.String = TestUtils.getParameter<kotlin.String>(fileName, "getClassificationByHcPartyId.ids")!!.let {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "getClassificationByHcPartyId") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? kotlin.String ?: it
                    }

                val response = api(credentialsFile).getClassificationByHcPartyId(ids = ids)

                val testFileName = "ClassificationApi.getClassificationByHcPartyId"
                val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                try {
                    val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ClassificationDto>? != null) {
                        if ("kotlin.collections.List<ClassificationDto>".contains("String>")) {
                            object : TypeReference<List<String>>() {}
                        } else {
                            object : TypeReference<List<ClassificationDto>>() {}
                        }
                    } else if(response as? kotlin.collections.Map<String, String>? != null){
                        object : TypeReference<Map<String,String>>() {}
                    } else {
                        object : TypeReference<kotlin.collections.List<ClassificationDto>>() {}
                    })
                    assertAreEquals("getClassificationByHcPartyId", objectFromFile, response)
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
            finally {
                TestUtils.deleteAfterElements(fileName)
                alreadyCreatedObjects.remove(fileName)
            }
        }
    }
    
    /**
     * Modify a classification Template
     *
     * Returns the modified classification Template.
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun modifyClassificationTest(fileName: String) = runBlocking {

        if (TestUtils.skipEndpoint(fileName, "modifyClassification")) {
            assertTrue(true, "Test of modifyClassification endpoint has been skipped")
        } else {
            try{
                createForModification(fileName)
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "modifyClassification")
                val classificationDto: ClassificationDto = TestUtils.getParameter<ClassificationDto>(fileName, "modifyClassification.classificationDto")!!.let {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "modifyClassification") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? ClassificationDto ?: it
                    }

                val response = api(credentialsFile).modifyClassification(classificationDto = classificationDto)

                val testFileName = "ClassificationApi.modifyClassification"
                val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                try {
                    val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ClassificationDto>? != null) {
                        if ("ClassificationDto".contains("String>")) {
                            object : TypeReference<List<String>>() {}
                        } else {
                            object : TypeReference<List<ClassificationDto>>() {}
                        }
                    } else if(response as? kotlin.collections.Map<String, String>? != null){
                        object : TypeReference<Map<String,String>>() {}
                    } else {
                        object : TypeReference<ClassificationDto>() {}
                    })
                    assertAreEquals("modifyClassification", objectFromFile, response)
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
            finally {
                TestUtils.deleteAfterElements(fileName)
                alreadyCreatedObjects.remove(fileName)
            }
        }
    }
    
    /**
     * Delegates a classification to a healthcare party
     *
     * It delegates a classification to a healthcare party (By current healthcare party). Returns the element with new delegations.
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun newClassificationDelegationsTest(fileName: String) = runBlocking {

        if (TestUtils.skipEndpoint(fileName, "newClassificationDelegations")) {
            assertTrue(true, "Test of newClassificationDelegations endpoint has been skipped")
        } else {
            try{
                createForModification(fileName)
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "newClassificationDelegations")
                val classificationId: kotlin.String = TestUtils.getParameter<kotlin.String>(fileName, "newClassificationDelegations.classificationId")!!.let {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "newClassificationDelegations") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } as? kotlin.String ?: it
                    }
                val delegationDto: kotlin.collections.List<DelegationDto> = TestUtils.getParameter<kotlin.collections.List<DelegationDto>>(fileName, "newClassificationDelegations.delegationDto")!!.map {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "newClassificationDelegations") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } ?: it
                    } as kotlin.collections.List<DelegationDto>

                val response = api(credentialsFile).newClassificationDelegations(classificationId = classificationId,delegationDto = delegationDto)

                val testFileName = "ClassificationApi.newClassificationDelegations"
                val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                try {
                    val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<ClassificationDto>? != null) {
                        if ("ClassificationDto".contains("String>")) {
                            object : TypeReference<List<String>>() {}
                        } else {
                            object : TypeReference<List<ClassificationDto>>() {}
                        }
                    } else if(response as? kotlin.collections.Map<String, String>? != null){
                        object : TypeReference<Map<String,String>>() {}
                    } else {
                        object : TypeReference<ClassificationDto>() {}
                    })
                    assertAreEquals("newClassificationDelegations", objectFromFile, response)
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
            finally {
                TestUtils.deleteAfterElements(fileName)
                alreadyCreatedObjects.remove(fileName)
            }
        }
    }
    
    /**
     * Update delegations in classification
     *
     * Keys must be delimited by coma
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun setClassificationsDelegationsTest(fileName: String) = runBlocking {

        if (TestUtils.skipEndpoint(fileName, "setClassificationsDelegations")) {
            assertTrue(true, "Test of setClassificationsDelegations endpoint has been skipped")
        } else {
            try{
                createForModification(fileName)
                val credentialsFile = TestUtils.getCredentialsFile(fileName, "setClassificationsDelegations")
                val icureStubDto: kotlin.collections.List<IcureStubDto> = TestUtils.getParameter<kotlin.collections.List<IcureStubDto>>(fileName, "setClassificationsDelegations.icureStubDto")!!.map {
                    (it as? ClassificationDto)?.takeIf { TestUtils.isAutoRev(fileName, "setClassificationsDelegations") }?.let {
                    val id = it::class.memberProperties.first { it.name == "id" }
                    val currentRev = api(credentialsFile).getClassification(id.getter.call(it) as String).rev
                    it.copy(rev = currentRev)
                    } ?: it
                    } as kotlin.collections.List<IcureStubDto>

                val response = api(credentialsFile).setClassificationsDelegations(icureStubDto = icureStubDto)

                val testFileName = "ClassificationApi.setClassificationsDelegations"
                val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
                try {
                    val objectFromFile = (response as? Flow<ByteBuffer>)?.let { file.readAsFlow() } ?: objectMapper.readValue(file,  if (response as? List<IcureStubDto>? != null) {
                        if ("kotlin.collections.List<IcureStubDto>".contains("String>")) {
                            object : TypeReference<List<String>>() {}
                        } else {
                            object : TypeReference<List<IcureStubDto>>() {}
                        }
                    } else if(response as? kotlin.collections.Map<String, String>? != null){
                        object : TypeReference<Map<String,String>>() {}
                    } else {
                        object : TypeReference<kotlin.collections.List<IcureStubDto>>() {}
                    })
                    assertAreEquals("setClassificationsDelegations", objectFromFile, response)
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
            finally {
                TestUtils.deleteAfterElements(fileName)
                alreadyCreatedObjects.remove(fileName)
            }
        }
    }
    

    private suspend fun assertAreEquals(functionName: String, objectFromFile: Any?, response: Any) {
        when {
            objectFromFile as? Iterable<Any> != null -> {
                val toSkip : kotlin.collections.List<String> = when {
                    functionName.let { name -> listOf("listContact", "modifyContacts").any { name.startsWith(it) } } -> listOf("subContacts.[created, rev, modified]", "services.[openingDate]", "groupId", "created", "modified", "rev")
                    functionName.let { name -> listOf("getServices").any { name.startsWith(it) } } -> listOf("rev", "created", "modified", "openingDate")
                    functionName.let { name -> listOf("create", "new", "get", "list", "set").any { name.startsWith(it) } } -> listOf("rev", "created", "modified")
                    functionName.let { name -> listOf("modify", "delete", "undelete").any { name.startsWith(it) } } -> listOf("rev")
                    functionName.let { name -> listOf("append").any { name.startsWith(it) } } -> listOf("id", "created", "modified")
                    functionName.let { name -> listOf("find", "filter").any { name.startsWith(it) } } -> listOf("rows.[created, rev, modified]", "created", "modified", "rev")
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
                assertTrue(diffs.isEmpty(), diffs.joinToString { it.toString() })
            }
            objectFromFile as? Flow<ByteBuffer> != null -> {
                assertTrue(objectFromFile.toList().let {
                    it.fold(0 to ByteArray(it.sumOf { it.remaining() })) { (pos, a), b ->
                        val siz = b.remaining()
                        (pos + siz) to a.also {
                            b.get(a, pos, siz)
                        }
                    }.second
                }.contentEquals(
                    (response as Flow<ByteBuffer>).toList().let {
                        it.fold(0 to ByteArray(it.sumOf { it.remaining() })) { (pos, a), b ->
                            val siz = b.remaining()
                            (pos + siz) to a.also {
                                b.get(a, pos, siz)
                            }
                        }.second
                    }
                )
                )}
            else -> {
                val toSkip : kotlin.collections.List<String> = when {
                    functionName.let { name -> listOf("modifyContact").any { name.startsWith(it) } } -> listOf("subContacts.[created, rev, modified]", "services.[openingDate]", "groupId", "created", "modified", "rev")
                    functionName.let { name -> listOf("modifyPatientReferral").any { name.startsWith(it) } } -> listOf("rev", "patientHealthCareParties.[referralPeriods]", "created", "modified")
                    functionName.let { name -> listOf("createContact").any { name.startsWith(it) } } -> listOf("rev", "created", "modified", "deletionDate", "groupId")
                    functionName.let { name -> listOf("newContactDelegations").any { name.startsWith(it) } } -> listOf("rev", "created", "modified", "groupId")
                    functionName.let { name -> listOf("create", "get", "modify", "new").any { name.startsWith(it) } } -> listOf("rev", "created", "modified", "deletionDate")
                    functionName.let { name -> listOf("set", "delete", "merge").any { name.startsWith(it) } } -> listOf("rev", "created", "modified")
                    functionName.let { name -> listOf("validate").any { name.startsWith(it) } } -> listOf("rev", "created", "modified", "sentDate")
                    functionName.let { name -> listOf("reassign").any { name.startsWith(it) } } -> listOf("id", "created", "invoicingCodes.id")
                    functionName.let { name -> listOf("find").any { name.startsWith(it) } } -> listOf("rows.[created, rev, modified]")
                    else -> emptyList()
                }
                val diffs = filterDiffs(objectFromFile, response, response.differences(objectFromFile), toSkip)
                assertTrue(diffs.isEmpty(), diffs.joinToString { it.toString() })
            }
        }
    }
}
