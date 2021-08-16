/**
 * iCure Cloud API Documentation
 *
 * Spring shop sample application
 *
 * The version of the OpenAPI document: v0.0.1
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
import io.icure.kraken.client.models.FrontEndMigrationDto

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
class FrontendmigrationApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Creates a front end migration
    * 
    * @param frontEndMigrationDto  
    * @return FrontEndMigrationDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createFrontEndMigration(frontEndMigrationDto: FrontEndMigrationDto) : FrontEndMigrationDto?  {
        val localVariableConfig = createFrontEndMigrationRequestConfig(frontEndMigrationDto = frontEndMigrationDto)

        return request<FrontEndMigrationDto, FrontEndMigrationDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createFrontEndMigration
    *
    * @param frontEndMigrationDto  
    * @return RequestConfig
    */
    fun createFrontEndMigrationRequestConfig(frontEndMigrationDto: FrontEndMigrationDto) : RequestConfig<FrontEndMigrationDto> {
        val localVariableBody = frontEndMigrationDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/frontendmigration",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Deletes a front end migration
    * 
    * @param frontEndMigrationId  
    * @return DocIdentifier
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteFrontEndMigration(frontEndMigrationId: kotlin.String) : DocIdentifier?  {
        val localVariableConfig = deleteFrontEndMigrationRequestConfig(frontEndMigrationId = frontEndMigrationId)

        return request<Unit, DocIdentifier>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation deleteFrontEndMigration
    *
    * @param frontEndMigrationId  
    * @return RequestConfig
    */
    fun deleteFrontEndMigrationRequestConfig(frontEndMigrationId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.DELETE,
            path = "/rest/v1/frontendmigration/{frontEndMigrationId}".replace("{"+"frontEndMigrationId"+"}", "$frontEndMigrationId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets a front end migration
    * 
    * @param frontEndMigrationId  
    * @return FrontEndMigrationDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getFrontEndMigration(frontEndMigrationId: kotlin.String) : FrontEndMigrationDto?  {
        val localVariableConfig = getFrontEndMigrationRequestConfig(frontEndMigrationId = frontEndMigrationId)

        return request<Unit, FrontEndMigrationDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getFrontEndMigration
    *
    * @param frontEndMigrationId  
    * @return RequestConfig
    */
    fun getFrontEndMigrationRequestConfig(frontEndMigrationId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/frontendmigration/{frontEndMigrationId}".replace("{"+"frontEndMigrationId"+"}", "$frontEndMigrationId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets an front end migration
    * 
    * @param frontEndMigrationName  
    * @return kotlin.collections.List<FrontEndMigrationDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getFrontEndMigrationByName(frontEndMigrationName: kotlin.String) : kotlin.collections.List<FrontEndMigrationDto>?  {
        val localVariableConfig = getFrontEndMigrationByNameRequestConfig(frontEndMigrationName = frontEndMigrationName)

        return request<Unit, kotlin.collections.List<FrontEndMigrationDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getFrontEndMigrationByName
    *
    * @param frontEndMigrationName  
    * @return RequestConfig
    */
    fun getFrontEndMigrationByNameRequestConfig(frontEndMigrationName: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/frontendmigration/byName/{frontEndMigrationName}".replace("{"+"frontEndMigrationName"+"}", "$frontEndMigrationName"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets a front end migration
    * 
    * @return kotlin.collections.List<FrontEndMigrationDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getFrontEndMigrations() : kotlin.collections.List<FrontEndMigrationDto>?  {
        val localVariableConfig = getFrontEndMigrationsRequestConfig()

        return request<Unit, kotlin.collections.List<FrontEndMigrationDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getFrontEndMigrations
    *
    * @return RequestConfig
    */
    fun getFrontEndMigrationsRequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/frontendmigration",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Modifies a front end migration
    * 
    * @param frontEndMigrationDto  
    * @return FrontEndMigrationDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyFrontEndMigration(frontEndMigrationDto: FrontEndMigrationDto) : FrontEndMigrationDto?  {
        val localVariableConfig = modifyFrontEndMigrationRequestConfig(frontEndMigrationDto = frontEndMigrationDto)

        return request<FrontEndMigrationDto, FrontEndMigrationDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyFrontEndMigration
    *
    * @param frontEndMigrationDto  
    * @return RequestConfig
    */
    fun modifyFrontEndMigrationRequestConfig(frontEndMigrationDto: FrontEndMigrationDto) : RequestConfig<FrontEndMigrationDto> {
        val localVariableBody = frontEndMigrationDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/frontendmigration",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
