/**
 * iCure Cloud API Documentation
 * Spring shop sample application
 *
 * OpenAPI spec version: v0.0.1
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */
package io.swagger.client.apis

import io.swagger.client.models.CodeDto
import io.swagger.client.models.FilterChainCode
import io.swagger.client.models.PaginatedListCodeDto

import io.swagger.client.infrastructure.*

class CodeApi(basePath: kotlin.String = "https://kraken.icure.dev") : ApiClient(basePath) {

    /**
     * Create a Code
     * Type, Code and Version are required.
     * @param body  
     * @return CodeDto
     */
    @Suppress("UNCHECKED_CAST")
    fun createCode(body: CodeDto): CodeDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/code"
        )
        val response = request<CodeDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as CodeDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Filter codes 
     * Returns a list of codes along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.
     * @param body  
     * @param startKey The start key for pagination, depends on the filters used (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional)
     * @param skip Skip rows (optional)
     * @param sort Sort key (optional)
     * @param desc Descending (optional)
     * @return PaginatedListCodeDto
     */
    @Suppress("UNCHECKED_CAST")
    fun filterCodesBy(body: FilterChainCode, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null, skip: kotlin.Int? = null, sort: kotlin.String? = null, desc: kotlin.Boolean? = null): PaginatedListCodeDto {
        val localVariableBody: kotlin.Any? = body
        val localVariableQuery: MultiValueMap = mapOf("startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"), "skip" to listOf("$skip"), "sort" to listOf("$sort"), "desc" to listOf("$desc"))
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/code/filter", query = localVariableQuery
        )
        val response = request<PaginatedListCodeDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListCodeDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Finding code types.
     * Returns a list of code types matched with given input.
     * @param region Code region (optional)
     * @param type Code type (optional)
     * @return kotlin.Array<kotlin.String>
     */
    @Suppress("UNCHECKED_CAST")
    fun findCodeTypes(region: kotlin.String? = null, type: kotlin.String? = null): kotlin.Array<kotlin.String> {
        val localVariableQuery: MultiValueMap = mapOf("region" to listOf("$region"), "type" to listOf("$type"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/code/codetype/byRegionType", query = localVariableQuery
        )
        val response = request<kotlin.Array<kotlin.String>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<kotlin.String>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Finding codes by code, type and version
     * Returns a list of codes matched with given input.
     * @param region Code region (optional)
     * @param type Code type (optional)
     * @param code Code code (optional)
     * @param version Code version (optional)
     * @return kotlin.Array<CodeDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun findCodes(region: kotlin.String? = null, type: kotlin.String? = null, code: kotlin.String? = null, version: kotlin.String? = null): kotlin.Array<CodeDto> {
        val localVariableQuery: MultiValueMap = mapOf("region" to listOf("$region"), "type" to listOf("$type"), "code" to listOf("$code"), "version" to listOf("$version"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/code/byRegionTypeCode", query = localVariableQuery
        )
        val response = request<kotlin.Array<CodeDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<CodeDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
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
     */
    @Suppress("UNCHECKED_CAST")
    fun findPaginatedCodes(region: kotlin.String? = null, type: kotlin.String? = null, code: kotlin.String? = null, version: kotlin.String? = null, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null): PaginatedListCodeDto {
        val localVariableQuery: MultiValueMap = mapOf("region" to listOf("$region"), "type" to listOf("$type"), "code" to listOf("$code"), "version" to listOf("$version"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/code", query = localVariableQuery
        )
        val response = request<PaginatedListCodeDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListCodeDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Finding codes by code, type and version with pagination.
     * Returns a list of codes matched with given input. If several types are provided, pagination is not supported
     * @param region  (optional)
     * @param types  (optional)
     * @param language  (optional)
     * @param label  (optional)
     * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#x27;s startKey (optional)
     * @param startDocumentId A code document ID (optional)
     * @param limit Number of rows (optional)
     * @return PaginatedListCodeDto
     */
    @Suppress("UNCHECKED_CAST")
    fun findPaginatedCodesByLabel(region: kotlin.String? = null, types: kotlin.String? = null, language: kotlin.String? = null, label: kotlin.String? = null, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null): PaginatedListCodeDto {
        val localVariableQuery: MultiValueMap = mapOf("region" to listOf("$region"), "types" to listOf("$types"), "language" to listOf("$language"), "label" to listOf("$label"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/code/byLabel", query = localVariableQuery
        )
        val response = request<PaginatedListCodeDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListCodeDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Finding codes by code, type and version with pagination.
     * Returns a list of codes matched with given input.
     * @param linkType  
     * @param linkedId  (optional)
     * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#x27;s startKey (optional)
     * @param startDocumentId A code document ID (optional)
     * @param limit Number of rows (optional)
     * @return PaginatedListCodeDto
     */
    @Suppress("UNCHECKED_CAST")
    fun findPaginatedCodesWithLink(linkType: kotlin.String, linkedId: kotlin.String? = null, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null): PaginatedListCodeDto {
        val localVariableQuery: MultiValueMap = mapOf("linkedId" to listOf("$linkedId"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/code/link/{linkType}".replace("{" + "linkType" + "}", "$linkType"), query = localVariableQuery
        )
        val response = request<PaginatedListCodeDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListCodeDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Finding tag types.
     * Returns a list of tag types matched with given input.
     * @param region Code region (optional)
     * @param type Code type (optional)
     * @return kotlin.Array<kotlin.String>
     */
    @Suppress("UNCHECKED_CAST")
    fun findTagTypes(region: kotlin.String? = null, type: kotlin.String? = null): kotlin.Array<kotlin.String> {
        val localVariableQuery: MultiValueMap = mapOf("region" to listOf("$region"), "type" to listOf("$type"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/code/tagtype/byRegionType", query = localVariableQuery
        )
        val response = request<kotlin.Array<kotlin.String>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<kotlin.String>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get a code
     * Get a code based on ID or (code,type,version) as query strings. (code,type,version) is unique.
     * @param codeId Code id 
     * @return CodeDto
     */
    @Suppress("UNCHECKED_CAST")
    fun getCode(codeId: kotlin.String): CodeDto {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/code/{codeId}".replace("{" + "codeId" + "}", "$codeId")
        )
        val response = request<CodeDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as CodeDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get a code
     * Get a code based on ID or (code,type,version) as query strings. (code,type,version) is unique.
     * @param type Code type 
     * @param code Code code 
     * @param version Code version 
     * @return CodeDto
     */
    @Suppress("UNCHECKED_CAST")
    fun getCodeWithParts(type: kotlin.String, code: kotlin.String, version: kotlin.String): CodeDto {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/code/{type}/{code}/{version}".replace("{" + "type" + "}", "$type").replace("{" + "code" + "}", "$code").replace("{" + "version" + "}", "$version")
        )
        val response = request<CodeDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as CodeDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get a list of codes by ids
     * Keys must be delimited by coma
     * @param codeIds  
     * @return kotlin.Array<CodeDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun getCodes(codeIds: kotlin.String): kotlin.Array<CodeDto> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/code/byIds/{codeIds}".replace("{" + "codeIds" + "}", "$codeIds")
        )
        val response = request<kotlin.Array<CodeDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<CodeDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Modify a code
     * Modification of (type, code, version) is not allowed.
     * @param body  
     * @return CodeDto
     */
    @Suppress("UNCHECKED_CAST")
    fun modifyCode(body: CodeDto): CodeDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.PUT,
                "/rest/v1/code"
        )
        val response = request<CodeDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as CodeDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
}
