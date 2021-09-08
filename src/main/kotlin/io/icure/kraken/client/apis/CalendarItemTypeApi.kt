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
import io.icure.kraken.client.models.CalendarItemTypeDto
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
class CalendarItemTypeApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Creates a calendarItemType
    * 
    * @param calendarItemTypeDto  
    * @return CalendarItemTypeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createCalendarItemType(calendarItemTypeDto: CalendarItemTypeDto) : CalendarItemTypeDto  {
        val localVariableConfig = createCalendarItemTypeRequestConfig(calendarItemTypeDto = calendarItemTypeDto)

        return request<CalendarItemTypeDto, CalendarItemTypeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation createCalendarItemType
    *
    * @param calendarItemTypeDto  
    * @return RequestConfig
    */
    fun createCalendarItemTypeRequestConfig(calendarItemTypeDto: CalendarItemTypeDto) : RequestConfig<CalendarItemTypeDto> {
        val localVariableBody = calendarItemTypeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/calendarItemType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Creates a calendarItemType
    * 
    * @param calendarItemTypeDto  
    * @return CalendarItemTypeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createCalendarItemType1(calendarItemTypeDto: CalendarItemTypeDto) : CalendarItemTypeDto?  {
        val localVariableConfig = createCalendarItemType1RequestConfig(calendarItemTypeDto = calendarItemTypeDto)

        return request<CalendarItemTypeDto, CalendarItemTypeDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createCalendarItemType1
    *
    * @param calendarItemTypeDto  
    * @return RequestConfig
    */
    fun createCalendarItemType1RequestConfig(calendarItemTypeDto: CalendarItemTypeDto) : RequestConfig<CalendarItemTypeDto> {
        val localVariableBody = calendarItemTypeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/calendarItemType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Deletes an calendarItemType
    * 
    * @param calendarItemTypeIds  
    * @return kotlin.collections.List<DocIdentifier>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteCalendarItemType(calendarItemTypeIds: kotlin.String) : kotlin.collections.List<DocIdentifier>  {
        val localVariableConfig = deleteCalendarItemTypeRequestConfig(calendarItemTypeIds = calendarItemTypeIds)

        return request<Unit, kotlin.collections.List<DocIdentifier>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation deleteCalendarItemType
    *
    * @param calendarItemTypeIds  
    * @return RequestConfig
    */
    fun deleteCalendarItemTypeRequestConfig(calendarItemTypeIds: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.DELETE,
            path = "/rest/v1/calendarItemType/{calendarItemTypeIds}".replace("{"+"calendarItemTypeIds"+"}", "$calendarItemTypeIds"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Deletes calendarItemTypes
    * 
    * @param listOfIdsDto  
    * @return kotlin.collections.List<DocIdentifier>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteCalendarItemTypes(listOfIdsDto: ListOfIdsDto) : kotlin.collections.List<DocIdentifier>?  {
        val localVariableConfig = deleteCalendarItemTypesRequestConfig(listOfIdsDto = listOfIdsDto)

        return request<ListOfIdsDto, kotlin.collections.List<DocIdentifier>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation deleteCalendarItemTypes
    *
    * @param listOfIdsDto  
    * @return RequestConfig
    */
    fun deleteCalendarItemTypesRequestConfig(listOfIdsDto: ListOfIdsDto) : RequestConfig<ListOfIdsDto> {
        val localVariableBody = listOfIdsDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/calendarItemType/delete/batch",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets a calendarItemType
    * 
    * @param calendarItemTypeId  
    * @return CalendarItemTypeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCalendarItemType(calendarItemTypeId: kotlin.String) : CalendarItemTypeDto  {
        val localVariableConfig = getCalendarItemTypeRequestConfig(calendarItemTypeId = calendarItemTypeId)

        return request<Unit, CalendarItemTypeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation getCalendarItemType
    *
    * @param calendarItemTypeId  
    * @return RequestConfig
    */
    fun getCalendarItemTypeRequestConfig(calendarItemTypeId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/calendarItemType/{calendarItemTypeId}".replace("{"+"calendarItemTypeId"+"}", "$calendarItemTypeId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets an calendarItemType
    * 
    * @param calendarItemTypeId  
    * @return CalendarItemTypeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCalendarItemType1(calendarItemTypeId: kotlin.String) : CalendarItemTypeDto?  {
        val localVariableConfig = getCalendarItemType1RequestConfig(calendarItemTypeId = calendarItemTypeId)

        return request<Unit, CalendarItemTypeDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getCalendarItemType1
    *
    * @param calendarItemTypeId  
    * @return RequestConfig
    */
    fun getCalendarItemType1RequestConfig(calendarItemTypeId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/calendarItemType/{calendarItemTypeId}".replace("{"+"calendarItemTypeId"+"}", "$calendarItemTypeId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets all calendarItemTypes
    * 
    * @return kotlin.collections.List<CalendarItemTypeDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCalendarItemTypes() : kotlin.collections.List<CalendarItemTypeDto>  {
        val localVariableConfig = getCalendarItemTypesRequestConfig()

        return request<Unit, kotlin.collections.List<CalendarItemTypeDto>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation getCalendarItemTypes
    *
    * @return RequestConfig
    */
    fun getCalendarItemTypesRequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/calendarItemType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets all calendarItemTypes
    * 
    * @return kotlin.collections.List<CalendarItemTypeDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCalendarItemTypes1() : kotlin.collections.List<CalendarItemTypeDto>?  {
        val localVariableConfig = getCalendarItemTypes1RequestConfig()

        return request<Unit, kotlin.collections.List<CalendarItemTypeDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getCalendarItemTypes1
    *
    * @return RequestConfig
    */
    fun getCalendarItemTypes1RequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/calendarItemType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets all calendarItemTypes include deleted
    * 
    * @return kotlin.collections.List<CalendarItemTypeDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCalendarItemTypesIncludeDeleted() : kotlin.collections.List<CalendarItemTypeDto>  {
        val localVariableConfig = getCalendarItemTypesIncludeDeletedRequestConfig()

        return request<Unit, kotlin.collections.List<CalendarItemTypeDto>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation getCalendarItemTypesIncludeDeleted
    *
    * @return RequestConfig
    */
    fun getCalendarItemTypesIncludeDeletedRequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/calendarItemType/includeDeleted",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets all calendarItemTypes include deleted
    * 
    * @return kotlin.collections.List<CalendarItemTypeDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCalendarItemTypesIncludeDeleted1() : kotlin.collections.List<CalendarItemTypeDto>?  {
        val localVariableConfig = getCalendarItemTypesIncludeDeleted1RequestConfig()

        return request<Unit, kotlin.collections.List<CalendarItemTypeDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getCalendarItemTypesIncludeDeleted1
    *
    * @return RequestConfig
    */
    fun getCalendarItemTypesIncludeDeleted1RequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/calendarItemType/includeDeleted",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Modifies an calendarItemType
    * 
    * @param calendarItemTypeDto  
    * @return CalendarItemTypeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyCalendarItemType(calendarItemTypeDto: CalendarItemTypeDto) : CalendarItemTypeDto  {
        val localVariableConfig = modifyCalendarItemTypeRequestConfig(calendarItemTypeDto = calendarItemTypeDto)

        return request<CalendarItemTypeDto, CalendarItemTypeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation modifyCalendarItemType
    *
    * @param calendarItemTypeDto  
    * @return RequestConfig
    */
    fun modifyCalendarItemTypeRequestConfig(calendarItemTypeDto: CalendarItemTypeDto) : RequestConfig<CalendarItemTypeDto> {
        val localVariableBody = calendarItemTypeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v2/calendarItemType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Modifies an calendarItemType
    * 
    * @param calendarItemTypeDto  
    * @return CalendarItemTypeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyCalendarItemType1(calendarItemTypeDto: CalendarItemTypeDto) : CalendarItemTypeDto?  {
        val localVariableConfig = modifyCalendarItemType1RequestConfig(calendarItemTypeDto = calendarItemTypeDto)

        return request<CalendarItemTypeDto, CalendarItemTypeDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyCalendarItemType1
    *
    * @param calendarItemTypeDto  
    * @return RequestConfig
    */
    fun modifyCalendarItemType1RequestConfig(calendarItemTypeDto: CalendarItemTypeDto) : RequestConfig<CalendarItemTypeDto> {
        val localVariableBody = calendarItemTypeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/calendarItemType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
