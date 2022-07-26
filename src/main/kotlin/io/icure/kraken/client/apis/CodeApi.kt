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

import io.icure.asyncjacksonhttpclient.net.web.WebClient
import io.icure.asyncjacksonhttpclient.netty.NettyWebClient
import io.icure.kraken.client.infrastructure.*

import io.icure.kraken.client.models.CodeDto

import io.icure.kraken.client.models.ListOfIdsDto
import io.icure.kraken.client.models.PaginatedListCodeDto

import kotlinx.coroutines.ExperimentalCoroutinesApi

import io.icure.kraken.client.infrastructure.ApiClient
import io.icure.kraken.client.infrastructure.ClientException
import io.icure.kraken.client.infrastructure.ServerException
import io.icure.kraken.client.infrastructure.MultiValueMap
import io.icure.kraken.client.infrastructure.RequestConfig
import io.icure.kraken.client.infrastructure.RequestMethod
import kotlinx.coroutines.flow.flowOf
import java.nio.ByteBuffer
import java.util.*
import javax.inject.Named
import kotlinx.coroutines.flow.Flow
import java.net.URLEncoder

@Named
@ExperimentalStdlibApi
@ExperimentalCoroutinesApi
class CodeApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Create a Code
    * Type, Code and Version are required.
    * @param codeDto  
    * @return CodeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createCode(codeDto: CodeDto) : CodeDto  {
        val localVariableConfig = createCodeRequestConfig(codeDto = codeDto)

        return request<CodeDto, CodeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation createCode
    *
    * @param codeDto  
    * @return RequestConfig
    */
    fun createCodeRequestConfig(codeDto: CodeDto) : RequestConfig<CodeDto> {
        // val localVariableBody = codeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/json")
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = codeDto

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/code",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Create a batch of codes
    * Create a batch of code entities. Fields Type, Code and Version are required for each code.
    * @param codeDto  
    * @return kotlin.collections.List<CodeDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createCodes(codeDto: kotlin.collections.List<CodeDto>) : kotlin.collections.List<CodeDto>  {
        val localVariableConfig = createCodesRequestConfig(codeDto = codeDto)

        return request<kotlin.collections.List<CodeDto>, kotlin.collections.List<CodeDto>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation createCodes
    *
    * @param codeDto  
    * @return RequestConfig
    */
    fun createCodesRequestConfig(codeDto: kotlin.collections.List<CodeDto>) : RequestConfig<kotlin.collections.List<CodeDto>> {
        // val localVariableBody = codeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/json")
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = codeDto

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/code/batch",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Filter codes 
    * Returns a list of codes along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.
    * @param startKey The start key for pagination, depends on the filters used (optional)
    * @param startDocumentId A patient document ID (optional)
    * @param limit Number of rows (optional)
    * @param skip Skip rows (optional)
    * @param sort Sort key (optional)
    * @param desc Descending (optional)
    * @param filterChainCode  (optional)
    * @return PaginatedListCodeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun filterCodesBy(startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?, skip: kotlin.Int?, sort: kotlin.String?, desc: kotlin.Boolean?, filterChainCode: io.icure.kraken.client.models.filter.chain.FilterChain<io.icure.kraken.client.models.CodeDto>?) : PaginatedListCodeDto  {
        val localVariableConfig = filterCodesByRequestConfig(startKey = startKey, startDocumentId = startDocumentId, limit = limit, skip = skip, sort = sort, desc = desc, filterChainCode = filterChainCode)

        return request<io.icure.kraken.client.models.filter.chain.FilterChain<io.icure.kraken.client.models.CodeDto>, PaginatedListCodeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation filterCodesBy
    *
    * @param startKey The start key for pagination, depends on the filters used (optional)
    * @param startDocumentId A patient document ID (optional)
    * @param limit Number of rows (optional)
    * @param skip Skip rows (optional)
    * @param sort Sort key (optional)
    * @param desc Descending (optional)
    * @param filterChainCode  (optional)
    * @return RequestConfig
    */
    fun filterCodesByRequestConfig(startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?, skip: kotlin.Int?, sort: kotlin.String?, desc: kotlin.Boolean?, filterChainCode: io.icure.kraken.client.models.filter.chain.FilterChain<io.icure.kraken.client.models.CodeDto>?) : RequestConfig<io.icure.kraken.client.models.filter.chain.FilterChain<io.icure.kraken.client.models.CodeDto>> {
        // val localVariableBody = filterChainCode
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (startKey != null) {
                    put("startKey", listOf(startKey.toString()))
                }
                if (startDocumentId != null) {
                    put("startDocumentId", listOf(startDocumentId.toString()))
                }
                if (limit != null) {
                    put("limit", listOf(limit.toString()))
                }
                if (skip != null) {
                    put("skip", listOf(skip.toString()))
                }
                if (sort != null) {
                    put("sort", listOf(sort.toString()))
                }
                if (desc != null) {
                    put("desc", listOf(desc.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/json")
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = filterChainCode

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/code/filter",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Finding codes by code, type and version with pagination.
    * Returns a list of codes matched with given input. If several types are provided, pagination is not supported
    * @param region  (optional)
    * @param types  (optional)
    * @param language  (optional)
    * @param label  (optional)
    * @param version  (optional)
    * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey (optional)
    * @param startDocumentId A code document ID (optional)
    * @param limit Number of rows (optional)
    * @return PaginatedListCodeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun findCodesByLabel(region: kotlin.String?, types: kotlin.String?, language: kotlin.String?, label: kotlin.String?, version: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : PaginatedListCodeDto  {
        val localVariableConfig = findCodesByLabelRequestConfig(region = region, types = types, language = language, label = label, version = version, startKey = startKey, startDocumentId = startDocumentId, limit = limit)

        return request<Unit, PaginatedListCodeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation findCodesByLabel
    *
    * @param region  (optional)
    * @param types  (optional)
    * @param language  (optional)
    * @param label  (optional)
    * @param version  (optional)
    * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey (optional)
    * @param startDocumentId A code document ID (optional)
    * @param limit Number of rows (optional)
    * @return RequestConfig
    */
    fun findCodesByLabelRequestConfig(region: kotlin.String?, types: kotlin.String?, language: kotlin.String?, label: kotlin.String?, version: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : RequestConfig<Unit> {
        // val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (region != null) {
                    put("region", listOf(region.toString()))
                }
                if (types != null) {
                    put("types", listOf(types.toString()))
                }
                if (language != null) {
                    put("language", listOf(language.toString()))
                }
                if (label != null) {
                    put("label", listOf(label.toString()))
                }
                if (version != null) {
                    put("version", listOf(version.toString()))
                }
                if (startKey != null) {
                    put("startKey", listOf(startKey.toString()))
                }
                if (startDocumentId != null) {
                    put("startDocumentId", listOf(startDocumentId.toString()))
                }
                if (limit != null) {
                    put("limit", listOf(limit.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = null

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/code/byLabel",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Finding codes by code, type and version with pagination.
    * Returns a list of codes matched with given input.
    * @param linkType  
    * @param linkedId  (optional)
    * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey (optional)
    * @param startDocumentId A code document ID (optional)
    * @param limit Number of rows (optional)
    * @return PaginatedListCodeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun findCodesByLink(linkType: kotlin.String, linkedId: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : PaginatedListCodeDto  {
        val localVariableConfig = findCodesByLinkRequestConfig(linkType = linkType, linkedId = linkedId, startKey = startKey, startDocumentId = startDocumentId, limit = limit)

        return request<Unit, PaginatedListCodeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation findCodesByLink
    *
    * @param linkType  
    * @param linkedId  (optional)
    * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey (optional)
    * @param startDocumentId A code document ID (optional)
    * @param limit Number of rows (optional)
    * @return RequestConfig
    */
    fun findCodesByLinkRequestConfig(linkType: kotlin.String, linkedId: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : RequestConfig<Unit> {
        // val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (linkedId != null) {
                    put("linkedId", listOf(linkedId.toString()))
                }
                if (startKey != null) {
                    put("startKey", listOf(startKey.toString()))
                }
                if (startDocumentId != null) {
                    put("startDocumentId", listOf(startDocumentId.toString()))
                }
                if (limit != null) {
                    put("limit", listOf(limit.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = null

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/code/byLink/{linkType}".replace("{"+"linkType"+"}", "${URLEncoder.encode(linkType.toString(), Charsets.UTF_8)}"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Finding codes by code, type and version with pagination.
    * Returns a list of codes matched with given input.
    * @param region  (optional)
    * @param type  (optional)
    * @param code  (optional)
    * @param version  (optional)
    * @param startKey The start key for pagination (optional)
    * @param startDocumentId A code document ID (optional)
    * @param limit Number of rows (optional)
    * @return PaginatedListCodeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun findCodesByType(region: kotlin.String?, type: kotlin.String?, code: kotlin.String?, version: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : PaginatedListCodeDto  {
        val localVariableConfig = findCodesByTypeRequestConfig(region = region, type = type, code = code, version = version, startKey = startKey, startDocumentId = startDocumentId, limit = limit)

        return request<Unit, PaginatedListCodeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation findCodesByType
    *
    * @param region  (optional)
    * @param type  (optional)
    * @param code  (optional)
    * @param version  (optional)
    * @param startKey The start key for pagination (optional)
    * @param startDocumentId A code document ID (optional)
    * @param limit Number of rows (optional)
    * @return RequestConfig
    */
    fun findCodesByTypeRequestConfig(region: kotlin.String?, type: kotlin.String?, code: kotlin.String?, version: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : RequestConfig<Unit> {
        // val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (region != null) {
                    put("region", listOf(region.toString()))
                }
                if (type != null) {
                    put("type", listOf(type.toString()))
                }
                if (code != null) {
                    put("code", listOf(code.toString()))
                }
                if (version != null) {
                    put("version", listOf(version.toString()))
                }
                if (startKey != null) {
                    put("startKey", listOf(startKey.toString()))
                }
                if (startDocumentId != null) {
                    put("startDocumentId", listOf(startDocumentId.toString()))
                }
                if (limit != null) {
                    put("limit", listOf(limit.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = null

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/code",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Get a code
    * Get a code based on ID or (code,type,version) as query strings. (code,type,version) is unique.
    * @param codeId Code id 
    * @return CodeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCode(codeId: kotlin.String) : CodeDto  {
        val localVariableConfig = getCodeRequestConfig(codeId = codeId)

        return request<Unit, CodeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation getCode
    *
    * @param codeId Code id 
    * @return RequestConfig
    */
    fun getCodeRequestConfig(codeId: kotlin.String) : RequestConfig<Unit> {
        // val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = null

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/code/{codeId}".replace("{"+"codeId"+"}", "${URLEncoder.encode(codeId.toString(), Charsets.UTF_8)}"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Get a code
    * Get a code based on ID or (code,type,version) as query strings. (code,type,version) is unique.
    * @param type Code type 
    * @param code Code code 
    * @param version Code version 
    * @return CodeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCodeWithParts(type: kotlin.String, code: kotlin.String, version: kotlin.String) : CodeDto  {
        val localVariableConfig = getCodeWithPartsRequestConfig(type = type, code = code, version = version)

        return request<Unit, CodeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation getCodeWithParts
    *
    * @param type Code type 
    * @param code Code code 
    * @param version Code version 
    * @return RequestConfig
    */
    fun getCodeWithPartsRequestConfig(type: kotlin.String, code: kotlin.String, version: kotlin.String) : RequestConfig<Unit> {
        // val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = null

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/code/{type}/{code}/{version}".replace("{"+"type"+"}", "${URLEncoder.encode(type.toString(), Charsets.UTF_8)}").replace("{"+"code"+"}", "${URLEncoder.encode(code.toString(), Charsets.UTF_8)}").replace("{"+"version"+"}", "${URLEncoder.encode(version.toString(), Charsets.UTF_8)}"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Get a list of codes by ids
    * Keys must be delimited by coma
    * @param listOfIdsDto  
    * @return kotlin.collections.List<CodeDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCodes(listOfIdsDto: ListOfIdsDto) : kotlin.collections.List<CodeDto>  {
        val localVariableConfig = getCodesRequestConfig(listOfIdsDto = listOfIdsDto)

        return request<ListOfIdsDto, kotlin.collections.List<CodeDto>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation getCodes
    *
    * @param listOfIdsDto  
    * @return RequestConfig
    */
    fun getCodesRequestConfig(listOfIdsDto: ListOfIdsDto) : RequestConfig<ListOfIdsDto> {
        // val localVariableBody = listOfIdsDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/json")
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = listOfIdsDto

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/code/byIds",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Import codes
    * Import codes from the resources XML file depending on the passed pathVariable
    * @param codeType  
    * @return kotlin.Any
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun importCodes(codeType: kotlin.String) : kotlin.Any  {
        val localVariableConfig = importCodesRequestConfig(codeType = codeType)

        return request<Unit, kotlin.Any>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation importCodes
    *
    * @param codeType  
    * @return RequestConfig
    */
    fun importCodesRequestConfig(codeType: kotlin.String) : RequestConfig<Unit> {
        // val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = null

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/code/{codeType}".replace("{"+"codeType"+"}", "${URLEncoder.encode(codeType.toString(), Charsets.UTF_8)}"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Finding code types.
    * Returns a list of code types matched with given input.
    * @param region Code region (optional)
    * @param type Code type (optional)
    * @return kotlin.collections.List<kotlin.String>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun listCodeTypesBy(region: kotlin.String?, type: kotlin.String?) : kotlin.collections.List<kotlin.String>  {
        val localVariableConfig = listCodeTypesByRequestConfig(region = region, type = type)

        return request<Unit, kotlin.collections.List<kotlin.String>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation listCodeTypesBy
    *
    * @param region Code region (optional)
    * @param type Code type (optional)
    * @return RequestConfig
    */
    fun listCodeTypesByRequestConfig(region: kotlin.String?, type: kotlin.String?) : RequestConfig<Unit> {
        // val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (region != null) {
                    put("region", listOf(region.toString()))
                }
                if (type != null) {
                    put("type", listOf(type.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = null

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/code/codetype/byRegionType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Finding codes by code, type and version
    * Returns a list of codes matched with given input.
    * @param region Code region (optional)
    * @param type Code type (optional)
    * @param code Code code (optional)
    * @param version Code version (optional)
    * @return kotlin.collections.List<CodeDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun listCodesByRegionTypeCodeVersion(region: kotlin.String?, type: kotlin.String?, code: kotlin.String?, version: kotlin.String?) : kotlin.collections.List<CodeDto>  {
        val localVariableConfig = listCodesByRegionTypeCodeVersionRequestConfig(region = region, type = type, code = code, version = version)

        return request<Unit, kotlin.collections.List<CodeDto>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation listCodesByRegionTypeCodeVersion
    *
    * @param region Code region (optional)
    * @param type Code type (optional)
    * @param code Code code (optional)
    * @param version Code version (optional)
    * @return RequestConfig
    */
    fun listCodesByRegionTypeCodeVersionRequestConfig(region: kotlin.String?, type: kotlin.String?, code: kotlin.String?, version: kotlin.String?) : RequestConfig<Unit> {
        // val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (region != null) {
                    put("region", listOf(region.toString()))
                }
                if (type != null) {
                    put("type", listOf(type.toString()))
                }
                if (code != null) {
                    put("code", listOf(code.toString()))
                }
                if (version != null) {
                    put("version", listOf(version.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = null

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/code/byRegionTypeCode",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Finding tag types.
    * Returns a list of tag types matched with given input.
    * @param region Code region (optional)
    * @param type Code type (optional)
    * @return kotlin.collections.List<kotlin.String>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun listTagTypesBy(region: kotlin.String?, type: kotlin.String?) : kotlin.collections.List<kotlin.String>  {
        val localVariableConfig = listTagTypesByRequestConfig(region = region, type = type)

        return request<Unit, kotlin.collections.List<kotlin.String>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation listTagTypesBy
    *
    * @param region Code region (optional)
    * @param type Code type (optional)
    * @return RequestConfig
    */
    fun listTagTypesByRequestConfig(region: kotlin.String?, type: kotlin.String?) : RequestConfig<Unit> {
        // val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (region != null) {
                    put("region", listOf(region.toString()))
                }
                if (type != null) {
                    put("type", listOf(type.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = null

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v2/code/tagtype/byRegionType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Get ids of code matching the provided filter for the current user (HcParty) 
    * 
    * @param abstractFilterDtoCode  
    * @return kotlin.collections.List<kotlin.String>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun matchCodesBy(abstractFilterDtoCode: io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.CodeDto>) : kotlin.collections.List<kotlin.String>  {
        val localVariableConfig = matchCodesByRequestConfig(abstractFilterDtoCode = abstractFilterDtoCode)

        return request<io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.CodeDto>, kotlin.collections.List<kotlin.String>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation matchCodesBy
    *
    * @param abstractFilterDtoCode  
    * @return RequestConfig
    */
    fun matchCodesByRequestConfig(abstractFilterDtoCode: io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.CodeDto>) : RequestConfig<io.icure.kraken.client.models.filter.AbstractFilterDto<io.icure.kraken.client.models.CodeDto>> {
        // val localVariableBody = abstractFilterDtoCode
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/json")
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = abstractFilterDtoCode

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/code/match",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Modify a code
    * Modification of (type, code, version) is not allowed.
    * @param codeDto  
    * @return CodeDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyCode(codeDto: CodeDto) : CodeDto  {
        val localVariableConfig = modifyCodeRequestConfig(codeDto = codeDto)

        return request<CodeDto, CodeDto>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation modifyCode
    *
    * @param codeDto  
    * @return RequestConfig
    */
    fun modifyCodeRequestConfig(codeDto: CodeDto) : RequestConfig<CodeDto> {
        // val localVariableBody = codeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/json")
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = codeDto

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v2/code",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Modify a batch of codes
    * Modification of (type, code, version) is not allowed.
    * @param codeDto  
    * @return kotlin.collections.List<CodeDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyCodes(codeDto: kotlin.collections.List<CodeDto>) : kotlin.collections.List<CodeDto>  {
        val localVariableConfig = modifyCodesRequestConfig(codeDto = codeDto)

        return request<kotlin.collections.List<CodeDto>, kotlin.collections.List<CodeDto>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation modifyCodes
    *
    * @param codeDto  
    * @return RequestConfig
    */
    fun modifyCodesRequestConfig(codeDto: kotlin.collections.List<CodeDto>) : RequestConfig<kotlin.collections.List<CodeDto>> {
        // val localVariableBody = codeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/json")
        localVariableHeaders["Accept"] = "*/*"
        val localVariableBody = codeDto

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v2/code/batch",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

}
