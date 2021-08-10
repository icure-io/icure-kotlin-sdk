/**
* iCure Cloud API Documentation
* Spring shop sample application
*
* The version of the OpenAPI document: v0.0.1
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
package io.icure.kraken.client.apis

import io.icure.asyncjacksonhttpclient.net.web.WebClient
import io.icure.asyncjacksonhttpclient.netty.NettyWebClient
import io.icure.kraken.client.models.CodeDto
import io.icure.kraken.client.models.FilterChainCode
import io.icure.kraken.client.models.PaginatedListCodeDto

import kotlinx.coroutines.ExperimentalCoroutinesApi

import io.icure.kraken.client.infrastructure.ApiClient
import io.icure.kraken.client.infrastructure.ClientException
import io.icure.kraken.client.infrastructure.ServerException
import io.icure.kraken.client.infrastructure.MultiValueMap
import io.icure.kraken.client.infrastructure.RequestConfig
import io.icure.kraken.client.infrastructure.RequestMethod
import javax.inject.Named

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
@Named
class CodeApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient()) : ApiClient(basePath, webClient) {
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
    suspend fun createCode(codeDto: CodeDto) : CodeDto?  {
        val localVariableConfig = createCodeRequestConfig(codeDto = codeDto)

        return request<CodeDto, CodeDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createCode
    *
    * @param codeDto  
    * @return RequestConfig
    */
    fun createCodeRequestConfig(codeDto: CodeDto) : RequestConfig<CodeDto> {
        val localVariableBody = codeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/code",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
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
    suspend fun filterCodesBy(startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?, skip: kotlin.Int?, sort: kotlin.String?, desc: kotlin.Boolean?, filterChainCode: FilterChainCode?) : PaginatedListCodeDto?  {
        val localVariableConfig = filterCodesByRequestConfig(startKey = startKey, startDocumentId = startDocumentId, limit = limit, skip = skip, sort = sort, desc = desc, filterChainCode = filterChainCode)

        return request<FilterChainCode, PaginatedListCodeDto>(
            localVariableConfig
        )
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
    fun filterCodesByRequestConfig(startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?, skip: kotlin.Int?, sort: kotlin.String?, desc: kotlin.Boolean?, filterChainCode: FilterChainCode?) : RequestConfig<FilterChainCode> {
        val localVariableBody = filterChainCode
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
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/code/filter",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
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
    suspend fun findCodeTypes(region: kotlin.String?, type: kotlin.String?) : kotlin.collections.List<kotlin.String>?  {
        val localVariableConfig = findCodeTypesRequestConfig(region = region, type = type)

        return request<Unit, kotlin.collections.List<kotlin.String>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findCodeTypes
    *
    * @param region Code region (optional)
    * @param type Code type (optional)
    * @return RequestConfig
    */
    fun findCodeTypesRequestConfig(region: kotlin.String?, type: kotlin.String?) : RequestConfig<Unit> {
        val localVariableBody = null
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

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/code/codetype/byRegionType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
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
    suspend fun findCodes(region: kotlin.String?, type: kotlin.String?, code: kotlin.String?, version: kotlin.String?) : kotlin.collections.List<CodeDto>?  {
        val localVariableConfig = findCodesRequestConfig(region = region, type = type, code = code, version = version)

        return request<Unit, kotlin.collections.List<CodeDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findCodes
    *
    * @param region Code region (optional)
    * @param type Code type (optional)
    * @param code Code code (optional)
    * @param version Code version (optional)
    * @return RequestConfig
    */
    fun findCodesRequestConfig(region: kotlin.String?, type: kotlin.String?, code: kotlin.String?, version: kotlin.String?) : RequestConfig<Unit> {
        val localVariableBody = null
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

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/code/byRegionTypeCode",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
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
    suspend fun findPaginatedCodes(region: kotlin.String?, type: kotlin.String?, code: kotlin.String?, version: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : PaginatedListCodeDto?  {
        val localVariableConfig = findPaginatedCodesRequestConfig(region = region, type = type, code = code, version = version, startKey = startKey, startDocumentId = startDocumentId, limit = limit)

        return request<Unit, PaginatedListCodeDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findPaginatedCodes
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
    fun findPaginatedCodesRequestConfig(region: kotlin.String?, type: kotlin.String?, code: kotlin.String?, version: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : RequestConfig<Unit> {
        val localVariableBody = null
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

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/code",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Finding codes by code, type and version with pagination.
    * Returns a list of codes matched with given input. If several types are provided, pagination is not supported
    * @param region  (optional)
    * @param types  (optional)
    * @param language  (optional)
    * @param label  (optional)
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
    suspend fun findPaginatedCodesByLabel(region: kotlin.String?, types: kotlin.String?, language: kotlin.String?, label: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : PaginatedListCodeDto?  {
        val localVariableConfig = findPaginatedCodesByLabelRequestConfig(region = region, types = types, language = language, label = label, startKey = startKey, startDocumentId = startDocumentId, limit = limit)

        return request<Unit, PaginatedListCodeDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findPaginatedCodesByLabel
    *
    * @param region  (optional)
    * @param types  (optional)
    * @param language  (optional)
    * @param label  (optional)
    * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey (optional)
    * @param startDocumentId A code document ID (optional)
    * @param limit Number of rows (optional)
    * @return RequestConfig
    */
    fun findPaginatedCodesByLabelRequestConfig(region: kotlin.String?, types: kotlin.String?, language: kotlin.String?, label: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : RequestConfig<Unit> {
        val localVariableBody = null
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

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/code/byLabel",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
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
    suspend fun findPaginatedCodesWithLink(linkType: kotlin.String, linkedId: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : PaginatedListCodeDto?  {
        val localVariableConfig = findPaginatedCodesWithLinkRequestConfig(linkType = linkType, linkedId = linkedId, startKey = startKey, startDocumentId = startDocumentId, limit = limit)

        return request<Unit, PaginatedListCodeDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findPaginatedCodesWithLink
    *
    * @param linkType  
    * @param linkedId  (optional)
    * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey (optional)
    * @param startDocumentId A code document ID (optional)
    * @param limit Number of rows (optional)
    * @return RequestConfig
    */
    fun findPaginatedCodesWithLinkRequestConfig(linkType: kotlin.String, linkedId: kotlin.String?, startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : RequestConfig<Unit> {
        val localVariableBody = null
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

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/code/link/{linkType}".replace("{"+"linkType"+"}", "$linkType"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
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
    suspend fun findTagTypes(region: kotlin.String?, type: kotlin.String?) : kotlin.collections.List<kotlin.String>?  {
        val localVariableConfig = findTagTypesRequestConfig(region = region, type = type)

        return request<Unit, kotlin.collections.List<kotlin.String>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findTagTypes
    *
    * @param region Code region (optional)
    * @param type Code type (optional)
    * @return RequestConfig
    */
    fun findTagTypesRequestConfig(region: kotlin.String?, type: kotlin.String?) : RequestConfig<Unit> {
        val localVariableBody = null
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

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/code/tagtype/byRegionType",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
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
    suspend fun getCode(codeId: kotlin.String) : CodeDto?  {
        val localVariableConfig = getCodeRequestConfig(codeId = codeId)

        return request<Unit, CodeDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getCode
    *
    * @param codeId Code id 
    * @return RequestConfig
    */
    fun getCodeRequestConfig(codeId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/code/{codeId}".replace("{"+"codeId"+"}", "$codeId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
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
    suspend fun getCodeWithParts(type: kotlin.String, code: kotlin.String, version: kotlin.String) : CodeDto?  {
        val localVariableConfig = getCodeWithPartsRequestConfig(type = type, code = code, version = version)

        return request<Unit, CodeDto>(
            localVariableConfig
        )
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
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/code/{type}/{code}/{version}".replace("{"+"type"+"}", "$type").replace("{"+"code"+"}", "$code").replace("{"+"version"+"}", "$version"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Get a list of codes by ids
    * Keys must be delimited by coma
    * @param codeIds  
    * @return kotlin.collections.List<CodeDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getCodes(codeIds: kotlin.String) : kotlin.collections.List<CodeDto>?  {
        val localVariableConfig = getCodesRequestConfig(codeIds = codeIds)

        return request<Unit, kotlin.collections.List<CodeDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getCodes
    *
    * @param codeIds  
    * @return RequestConfig
    */
    fun getCodesRequestConfig(codeIds: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/code/byIds/{codeIds}".replace("{"+"codeIds"+"}", "$codeIds"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
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
    suspend fun modifyCode(codeDto: CodeDto) : CodeDto?  {
        val localVariableConfig = modifyCodeRequestConfig(codeDto = codeDto)

        return request<CodeDto, CodeDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyCode
    *
    * @param codeDto  
    * @return RequestConfig
    */
    fun modifyCodeRequestConfig(codeDto: CodeDto) : RequestConfig<CodeDto> {
        val localVariableBody = codeDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/code",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
