/**
 * OpenAPI definition
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v0
 * 
 *
 * Please note:
 * This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * Do not edit this file manually.
 */
package io.icure.kraken.client.apis

import io.icure.asyncjacksonhttpclient.net.web.WebClient
import io.icure.asyncjacksonhttpclient.netty.NettyWebClient
import io.icure.kraken.client.models.AgendaDto
import io.icure.kraken.client.models.DocIdentifier
import io.icure.kraken.client.models.ListOfIdsDto

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
class AgendaApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Creates a agenda
    * 
    * @param agendaDto  
    * @return AgendaDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createAgenda(agendaDto: AgendaDto) : AgendaDto?  {
        val localVariableConfig = createAgendaRequestConfig(agendaDto = agendaDto)

        return request<AgendaDto, AgendaDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createAgenda
    *
    * @param agendaDto  
    * @return RequestConfig
    */
    fun createAgendaRequestConfig(agendaDto: AgendaDto) : RequestConfig<AgendaDto> {
        val localVariableBody = agendaDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/agenda",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Creates a agenda
    * 
    * @param agendaDto  
    * @return AgendaDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createAgenda1(agendaDto: AgendaDto) : AgendaDto?  {
        val localVariableConfig = createAgenda1RequestConfig(agendaDto = agendaDto)

        return request<AgendaDto, AgendaDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createAgenda1
    *
    * @param agendaDto  
    * @return RequestConfig
    */
    fun createAgenda1RequestConfig(agendaDto: AgendaDto) : RequestConfig<AgendaDto> {
        val localVariableBody = agendaDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/agenda",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Delete agendas by id
    * 
    * @param agendaIds  
    * @return kotlin.collections.List<DocIdentifier>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteAgenda(agendaIds: kotlin.String) : kotlin.collections.List<DocIdentifier>?  {
        val localVariableConfig = deleteAgendaRequestConfig(agendaIds = agendaIds)

        return request<Unit, kotlin.collections.List<DocIdentifier>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation deleteAgenda
    *
    * @param agendaIds  
    * @return RequestConfig
    */
    fun deleteAgendaRequestConfig(agendaIds: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.DELETE,
            path = "/rest/v1/agenda/{agendaIds}".replace("{"+"agendaIds"+"}", "$agendaIds"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Deletes agendas
    * 
    * @param listOfIdsDto  
    * @return kotlin.collections.List<DocIdentifier>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteAgendas(listOfIdsDto: ListOfIdsDto) : kotlin.collections.List<DocIdentifier>?  {
        val localVariableConfig = deleteAgendasRequestConfig(listOfIdsDto = listOfIdsDto)

        return request<ListOfIdsDto, kotlin.collections.List<DocIdentifier>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation deleteAgendas
    *
    * @param listOfIdsDto  
    * @return RequestConfig
    */
    fun deleteAgendasRequestConfig(listOfIdsDto: ListOfIdsDto) : RequestConfig<ListOfIdsDto> {
        val localVariableBody = listOfIdsDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/agenda/delete/batch",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets an agenda
    * 
    * @param agendaId  
    * @return AgendaDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getAgenda(agendaId: kotlin.String) : AgendaDto?  {
        val localVariableConfig = getAgendaRequestConfig(agendaId = agendaId)

        return request<Unit, AgendaDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getAgenda
    *
    * @param agendaId  
    * @return RequestConfig
    */
    fun getAgendaRequestConfig(agendaId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/agenda/{agendaId}".replace("{"+"agendaId"+"}", "$agendaId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets an agenda
    * 
    * @param agendaId  
    * @return AgendaDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getAgenda1(agendaId: kotlin.String) : AgendaDto?  {
        val localVariableConfig = getAgenda1RequestConfig(agendaId = agendaId)

        return request<Unit, AgendaDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getAgenda1
    *
    * @param agendaId  
    * @return RequestConfig
    */
    fun getAgenda1RequestConfig(agendaId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/agenda/{agendaId}".replace("{"+"agendaId"+"}", "$agendaId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets all agendas
    * 
    * @return kotlin.collections.List<AgendaDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getAgendas() : kotlin.collections.List<AgendaDto>?  {
        val localVariableConfig = getAgendasRequestConfig()

        return request<Unit, kotlin.collections.List<AgendaDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getAgendas
    *
    * @return RequestConfig
    */
    fun getAgendasRequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/agenda",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets all agendas
    * 
    * @return kotlin.collections.List<AgendaDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getAgendas1() : kotlin.collections.List<AgendaDto>?  {
        val localVariableConfig = getAgendas1RequestConfig()

        return request<Unit, kotlin.collections.List<AgendaDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getAgendas1
    *
    * @return RequestConfig
    */
    fun getAgendas1RequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/agenda",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets all agendas for user
    * 
    * @param userId  
    * @return AgendaDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getAgendasForUser(userId: kotlin.String) : AgendaDto?  {
        val localVariableConfig = getAgendasForUserRequestConfig(userId = userId)

        return request<Unit, AgendaDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getAgendasForUser
    *
    * @param userId  
    * @return RequestConfig
    */
    fun getAgendasForUserRequestConfig(userId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                put("userId", listOf(userId.toString()))
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/agenda/byUser",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets all agendas for user
    * 
    * @param userId  
    * @return AgendaDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getAgendasForUser1(userId: kotlin.String) : AgendaDto?  {
        val localVariableConfig = getAgendasForUser1RequestConfig(userId = userId)

        return request<Unit, AgendaDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getAgendasForUser1
    *
    * @param userId  
    * @return RequestConfig
    */
    fun getAgendasForUser1RequestConfig(userId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                put("userId", listOf(userId.toString()))
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/agenda/byUser",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets readable agendas for user
    * 
    * @param userId  
    * @return kotlin.collections.List<AgendaDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getReadableAgendasForUser(userId: kotlin.String) : kotlin.collections.List<AgendaDto>?  {
        val localVariableConfig = getReadableAgendasForUserRequestConfig(userId = userId)

        return request<Unit, kotlin.collections.List<AgendaDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getReadableAgendasForUser
    *
    * @param userId  
    * @return RequestConfig
    */
    fun getReadableAgendasForUserRequestConfig(userId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                put("userId", listOf(userId.toString()))
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/agenda/readableForUser",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets readable agendas for user
    * 
    * @param userId  
    * @return kotlin.collections.List<AgendaDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getReadableAgendasForUser1(userId: kotlin.String) : kotlin.collections.List<AgendaDto>?  {
        val localVariableConfig = getReadableAgendasForUser1RequestConfig(userId = userId)

        return request<Unit, kotlin.collections.List<AgendaDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getReadableAgendasForUser1
    *
    * @param userId  
    * @return RequestConfig
    */
    fun getReadableAgendasForUser1RequestConfig(userId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                put("userId", listOf(userId.toString()))
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/agenda/readableForUser",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Modifies an agenda
    * 
    * @param agendaDto  
    * @return AgendaDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyAgenda(agendaDto: AgendaDto) : AgendaDto?  {
        val localVariableConfig = modifyAgendaRequestConfig(agendaDto = agendaDto)

        return request<AgendaDto, AgendaDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyAgenda
    *
    * @param agendaDto  
    * @return RequestConfig
    */
    fun modifyAgendaRequestConfig(agendaDto: AgendaDto) : RequestConfig<AgendaDto> {
        val localVariableBody = agendaDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v2/agenda",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Modifies an agenda
    * 
    * @param agendaDto  
    * @return AgendaDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyAgenda1(agendaDto: AgendaDto) : AgendaDto?  {
        val localVariableConfig = modifyAgenda1RequestConfig(agendaDto = agendaDto)

        return request<AgendaDto, AgendaDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyAgenda1
    *
    * @param agendaDto  
    * @return RequestConfig
    */
    fun modifyAgenda1RequestConfig(agendaDto: AgendaDto) : RequestConfig<AgendaDto> {
        val localVariableBody = agendaDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/agenda",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
