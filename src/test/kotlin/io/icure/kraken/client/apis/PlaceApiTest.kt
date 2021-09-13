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
import io.icure.kraken.client.models.ListOfIdsDto
import io.icure.kraken.client.models.PlaceDto
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
import kotlin.reflect.full.callSuspendBy
import kotlin.reflect.javaType

/**
 * API tests for PlaceApi
 */
@ExperimentalStdlibApi
class PlaceApiTest() {

    companion object {
        private val alreadyCreatedObjects = mutableSetOf<String>()
        fun canCreateForModificationObjects(fileName: String) = alreadyCreatedObjects.add(fileName)

        @JvmStatic
        @AfterAll
        fun afterAllTests(){
        TestUtils.deleteAfterElements("PlaceApi.json")
        }

        @JvmStatic
        fun fileNames() = listOf("PlaceApi.json")
    }

    fun api(fileName: String) = PlaceApi(basePath = "https://kraken.icure.dev", authHeader = fileName.basicAuth())
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
                            PlaceDto::class.java -> it to objectMapper.convertValue(body, PlaceDto::class.java)
                            PlaceApi::class.java -> it to api(credentialsFile)
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
     * Creates a place
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun createPlaceTest(fileName: String) = runBlocking {
        createForModification(fileName)
		if (TestUtils.skipEndpoint(fileName, "createPlace")) {
			assert(true)
			println("Endpoint createPlace skipped")
		} else {
        val credentialsFile = TestUtils.getCredentialsFile(fileName, "createPlace")
        val placeDto: PlaceDto = TestUtils.getParameter(fileName, "createPlace.placeDto")!!
		if (placeDto as? Collection<*> == null) {
			placeDto.also {
            if (TestUtils.isAutoRev(fileName, "createPlace") && it != null) {
                val id = it::class.memberProperties.first { it.name == "id" }
                val currentRev = api(credentialsFile).getPlace(id.getter.call(it) as String).rev
                val rev = object: TypeReference<PlaceDto>(){}.type::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                rev.setter.call(it, currentRev)
                }
			}
		} else {
			val paramAsCollection = placeDto as? Collection<PlaceDto> ?: emptyList<PlaceDto>() as Collection<PlaceDto>
			paramAsCollection.forEach {
                if (TestUtils.isAutoRev(fileName, "createPlace") && it != null) {
                    val id = it::class.memberProperties.first { it.name == "id" }

                    val currentRev = api(credentialsFile).getPlace(id.getter.call(it) as String).rev
                    val rev = it::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                    rev.setter.call(it, currentRev)
                }
			}
		}

        val response = api(credentialsFile).createPlace(placeDto)

        val testFileName = "PlaceApi.createPlace"
        val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
        try {
            val objectFromFile = objectMapper.readValue(file,  if (response as? kotlin.collections.List<PlaceDto>? != null) {
                if ("PlaceDto".contains("String>")) {
                    object : TypeReference<List<String>>() {}
                } else {
                    object : TypeReference<List<PlaceDto>>() {}
                }
            } else if(response as? kotlin.collections.Map<String, String>? != null){
                object : TypeReference<Map<String,String>>() {}
            } else {
            object : TypeReference<Void>() {}
            })
            assertAreEquals("createPlace", objectFromFile, response)
			println("Comparison successful")
        } catch (e:FileNotFoundException) {
            file.parentFile.mkdirs()
            file.createNewFile()
            objectMapper.writeValue(file, response)
			assert(true)
			println("File written")
        }
    }}
    
    /**
     * Deletes places
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun deletePlacesTest(fileName: String) = runBlocking {
        createForModification(fileName)
		if (TestUtils.skipEndpoint(fileName, "deletePlaces")) {
			assert(true)
			println("Endpoint deletePlaces skipped")
		} else {
        val credentialsFile = TestUtils.getCredentialsFile(fileName, "deletePlaces")
        val listOfIdsDto: ListOfIdsDto = TestUtils.getParameter(fileName, "deletePlaces.listOfIdsDto")!!
		if (listOfIdsDto as? Collection<*> == null) {
			listOfIdsDto.also {
            if (TestUtils.isAutoRev(fileName, "deletePlaces") && it != null) {
                val id = it::class.memberProperties.first { it.name == "id" }
                val currentRev = api(credentialsFile).getPlace(id.getter.call(it) as String).rev
                val rev = object: TypeReference<ListOfIdsDto>(){}.type::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                rev.setter.call(it, currentRev)
                }
			}
		} else {
			val paramAsCollection = listOfIdsDto as? Collection<ListOfIdsDto> ?: emptyList<ListOfIdsDto>() as Collection<ListOfIdsDto>
			paramAsCollection.forEach {
                if (TestUtils.isAutoRev(fileName, "deletePlaces") && it != null) {
                    val id = it::class.memberProperties.first { it.name == "id" }

                    val currentRev = api(credentialsFile).getPlace(id.getter.call(it) as String).rev
                    val rev = it::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                    rev.setter.call(it, currentRev)
                }
			}
		}

        val response = api(credentialsFile).deletePlaces(listOfIdsDto)

        val testFileName = "PlaceApi.deletePlaces"
        val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
        try {
            val objectFromFile = objectMapper.readValue(file,  if (response as? kotlin.collections.List<DocIdentifier>? != null) {
                if ("kotlin.collections.List<DocIdentifier>".contains("String>")) {
                    object : TypeReference<List<String>>() {}
                } else {
                    object : TypeReference<List<DocIdentifier>>() {}
                }
            } else if(response as? kotlin.collections.Map<String, String>? != null){
                object : TypeReference<Map<String,String>>() {}
            } else {
            object : TypeReference<Void>() {}
            })
            assertAreEquals("deletePlaces", objectFromFile, response)
			println("Comparison successful")
        } catch (e:FileNotFoundException) {
            file.parentFile.mkdirs()
            file.createNewFile()
            objectMapper.writeValue(file, response)
			assert(true)
			println("File written")
        }
    }}
    
    /**
     * Gets an place
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun getPlaceTest(fileName: String) = runBlocking {
        createForModification(fileName)
		if (TestUtils.skipEndpoint(fileName, "getPlace")) {
			assert(true)
			println("Endpoint getPlace skipped")
		} else {
        val credentialsFile = TestUtils.getCredentialsFile(fileName, "getPlace")
        val placeId: kotlin.String = TestUtils.getParameter(fileName, "getPlace.placeId")!!
		if (placeId as? Collection<*> == null) {
			placeId.also {
            if (TestUtils.isAutoRev(fileName, "getPlace") && it != null) {
                val id = it::class.memberProperties.first { it.name == "id" }
                val currentRev = api(credentialsFile).getPlace(id.getter.call(it) as String).rev
                val rev = object: TypeReference<kotlin.String>(){}.type::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                rev.setter.call(it, currentRev)
                }
			}
		} else {
			val paramAsCollection = placeId as? Collection<kotlin.String> ?: emptyList<kotlin.String>() as Collection<kotlin.String>
			paramAsCollection.forEach {
                if (TestUtils.isAutoRev(fileName, "getPlace") && it != null) {
                    val id = it::class.memberProperties.first { it.name == "id" }

                    val currentRev = api(credentialsFile).getPlace(id.getter.call(it) as String).rev
                    val rev = it::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                    rev.setter.call(it, currentRev)
                }
			}
		}

        val response = api(credentialsFile).getPlace(placeId)

        val testFileName = "PlaceApi.getPlace"
        val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
        try {
            val objectFromFile = objectMapper.readValue(file,  if (response as? kotlin.collections.List<PlaceDto>? != null) {
                if ("PlaceDto".contains("String>")) {
                    object : TypeReference<List<String>>() {}
                } else {
                    object : TypeReference<List<PlaceDto>>() {}
                }
            } else if(response as? kotlin.collections.Map<String, String>? != null){
                object : TypeReference<Map<String,String>>() {}
            } else {
            object : TypeReference<Void>() {}
            })
            assertAreEquals("getPlace", objectFromFile, response)
			println("Comparison successful")
        } catch (e:FileNotFoundException) {
            file.parentFile.mkdirs()
            file.createNewFile()
            objectMapper.writeValue(file, response)
			assert(true)
			println("File written")
        }
    }}
    
    /**
     * Gets all places
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun getPlacesTest(fileName: String) = runBlocking {
        createForModification(fileName)
		if (TestUtils.skipEndpoint(fileName, "getPlaces")) {
			assert(true)
			println("Endpoint getPlaces skipped")
		} else {
        val credentialsFile = TestUtils.getCredentialsFile(fileName, "getPlaces")

        val response = api(credentialsFile).getPlaces()

        val testFileName = "PlaceApi.getPlaces"
        val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
        try {
            val objectFromFile = objectMapper.readValue(file,  if (response as? kotlin.collections.List<PlaceDto>? != null) {
                if ("kotlin.collections.List<PlaceDto>".contains("String>")) {
                    object : TypeReference<List<String>>() {}
                } else {
                    object : TypeReference<List<PlaceDto>>() {}
                }
            } else if(response as? kotlin.collections.Map<String, String>? != null){
                object : TypeReference<Map<String,String>>() {}
            } else {
            object : TypeReference<Void>() {}
            })
            assertAreEquals("getPlaces", objectFromFile, response)
			println("Comparison successful")
        } catch (e:FileNotFoundException) {
            file.parentFile.mkdirs()
            file.createNewFile()
            objectMapper.writeValue(file, response)
			assert(true)
			println("File written")
        }
    }}
    
    /**
     * Modifies an place
     *
     * 
     *
     * @throws ApiException
     *          if the Api call fails
     */
    @ParameterizedTest
    @MethodSource("fileNames") // six numbers
	fun modifyPlaceTest(fileName: String) = runBlocking {
        createForModification(fileName)
		if (TestUtils.skipEndpoint(fileName, "modifyPlace")) {
			assert(true)
			println("Endpoint modifyPlace skipped")
		} else {
        val credentialsFile = TestUtils.getCredentialsFile(fileName, "modifyPlace")
        val placeDto: PlaceDto = TestUtils.getParameter(fileName, "modifyPlace.placeDto")!!
		if (placeDto as? Collection<*> == null) {
			placeDto.also {
            if (TestUtils.isAutoRev(fileName, "modifyPlace") && it != null) {
                val id = it::class.memberProperties.first { it.name == "id" }
                val currentRev = api(credentialsFile).getPlace(id.getter.call(it) as String).rev
                val rev = object: TypeReference<PlaceDto>(){}.type::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                rev.setter.call(it, currentRev)
                }
			}
		} else {
			val paramAsCollection = placeDto as? Collection<PlaceDto> ?: emptyList<PlaceDto>() as Collection<PlaceDto>
			paramAsCollection.forEach {
                if (TestUtils.isAutoRev(fileName, "modifyPlace") && it != null) {
                    val id = it::class.memberProperties.first { it.name == "id" }

                    val currentRev = api(credentialsFile).getPlace(id.getter.call(it) as String).rev
                    val rev = it::class.memberProperties.filterIsInstance<KMutableProperty<*>>().first { it.name == "rev" }
                    rev.setter.call(it, currentRev)
                }
			}
		}

        val response = api(credentialsFile).modifyPlace(placeDto)

        val testFileName = "PlaceApi.modifyPlace"
        val file = File(workingFolder + File.separator + this::class.simpleName + File.separator + fileName, "$testFileName.json")
        try {
            val objectFromFile = objectMapper.readValue(file,  if (response as? kotlin.collections.List<PlaceDto>? != null) {
                if ("PlaceDto".contains("String>")) {
                    object : TypeReference<List<String>>() {}
                } else {
                    object : TypeReference<List<PlaceDto>>() {}
                }
            } else if(response as? kotlin.collections.Map<String, String>? != null){
                object : TypeReference<Map<String,String>>() {}
            } else {
            object : TypeReference<Void>() {}
            })
            assertAreEquals("modifyPlace", objectFromFile, response)
			println("Comparison successful")
        } catch (e:FileNotFoundException) {
            file.parentFile.mkdirs()
            file.createNewFile()
            objectMapper.writeValue(file, response)
			assert(true)
			println("File written")
        }
    }}
    


    private fun assertAreEquals(functionName: String, objectFromFile: Any?, response: Any) {
        if (objectFromFile as? Iterable<Any> != null) {
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
        } else {
            if (functionName.startsWith("create") || functionName.startsWith("modify")) {
                assertThat(objectFromFile as Any).isEqualToIgnoringGivenProperties(response, *(response::class.memberProperties.filter { it.name == "rev" || it.name == "id" || it.name == "created"  || it.name == "modified" }.mapNotNull { it as? KProperty1<Any, Any> }.toTypedArray()))
            } else {
                assertEquals(objectFromFile, response)
            }
        }
    }

}
