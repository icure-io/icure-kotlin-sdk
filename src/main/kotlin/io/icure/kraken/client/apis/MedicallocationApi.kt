/**
 * iCure Data Stack API Documentation
 *
 * The iCure Data Stack Application API is the native interface to iCure. This version is obsolete, please use v2.
 *
 * The version of the OpenAPI document: v1
 * 
 *
 * Please note:
 * This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * Do not edit this file manually.
 */
package io.icure.kraken.client.apis

import io.icure.asyncjacksonhttpclient.net.web.WebClient
import io.icure.asyncjacksonhttpclient.netty.NettyWebClient
import io.icure.kraken.client.models.DocIdentifier
import io.icure.kraken.client.models.MedicalLocationDto

import kotlinx.coroutines.ExperimentalCoroutinesApi

import io.icure.kraken.client.infrastructure.ApiClient
import io.icure.kraken.client.infrastructure.ClientException
import io.icure.kraken.client.infrastructure.ServerException
import io.icure.kraken.client.infrastructure.MultiValueMap
import io.icure.kraken.client.infrastructure.RequestConfig
import io.icure.kraken.client.infrastructure.RequestMethod
import javax.inject.Named

@Named
@ExperimentalStdlibApi
@ExperimentalCoroutinesApi
class MedicallocationApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "http://localhost:16043")
        }
    }

    /**
    * Creates a medical location
    * 
    * @param medicalLocationDto  
    * @return MedicalLocationDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createMedicalLocation(medicalLocationDto: MedicalLocationDto) : MedicalLocationDto?  {
        val localVariableConfig = createMedicalLocationRequestConfig(medicalLocationDto = medicalLocationDto)

        return request<MedicalLocationDto, MedicalLocationDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createMedicalLocation
    *
    * @param medicalLocationDto  
    * @return RequestConfig
    */
    fun createMedicalLocationRequestConfig(medicalLocationDto: MedicalLocationDto) : RequestConfig<MedicalLocationDto> {
        val localVariableBody = medicalLocationDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/medicallocation",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Deletes a medical location
    * 
    * @param locationIds  
    * @return kotlin.collections.List<DocIdentifier>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteMedicalLocation(locationIds: kotlin.String) : kotlin.collections.List<DocIdentifier>?  {
        val localVariableConfig = deleteMedicalLocationRequestConfig(locationIds = locationIds)

        return request<Unit, kotlin.collections.List<DocIdentifier>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation deleteMedicalLocation
    *
    * @param locationIds  
    * @return RequestConfig
    */
    fun deleteMedicalLocationRequestConfig(locationIds: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.DELETE,
            path = "/rest/v1/medicallocation/{locationIds}".replace("{"+"locationIds"+"}", "$locationIds"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets a medical location
    * 
    * @param locationId  
    * @return MedicalLocationDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getMedicalLocation(locationId: kotlin.String) : MedicalLocationDto?  {
        val localVariableConfig = getMedicalLocationRequestConfig(locationId = locationId)

        return request<Unit, MedicalLocationDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getMedicalLocation
    *
    * @param locationId  
    * @return RequestConfig
    */
    fun getMedicalLocationRequestConfig(locationId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/medicallocation/{locationId}".replace("{"+"locationId"+"}", "$locationId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets all medical locations
    * 
    * @return kotlin.collections.List<MedicalLocationDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getMedicalLocations() : kotlin.collections.List<MedicalLocationDto>?  {
        val localVariableConfig = getMedicalLocationsRequestConfig()

        return request<Unit, kotlin.collections.List<MedicalLocationDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getMedicalLocations
    *
    * @return RequestConfig
    */
    fun getMedicalLocationsRequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/medicallocation",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Modifies a medical location
    * 
    * @param medicalLocationDto  
    * @return MedicalLocationDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyMedicalLocation(medicalLocationDto: MedicalLocationDto) : MedicalLocationDto?  {
        val localVariableConfig = modifyMedicalLocationRequestConfig(medicalLocationDto = medicalLocationDto)

        return request<MedicalLocationDto, MedicalLocationDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyMedicalLocation
    *
    * @param medicalLocationDto  
    * @return RequestConfig
    */
    fun modifyMedicalLocationRequestConfig(medicalLocationDto: MedicalLocationDto) : RequestConfig<MedicalLocationDto> {
        val localVariableBody = medicalLocationDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/medicallocation",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
