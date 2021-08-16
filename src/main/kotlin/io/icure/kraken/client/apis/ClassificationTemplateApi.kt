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
import io.icure.kraken.client.models.ClassificationTemplateDto
import io.icure.kraken.client.models.DelegationDto
import io.icure.kraken.client.models.DocIdentifier
import io.icure.kraken.client.models.PaginatedListClassificationTemplateDto

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
class ClassificationTemplateApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Create a classification Template with the current user
    * Returns an instance of created classification Template.
    * @param classificationTemplateDto  
    * @return ClassificationTemplateDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createClassificationTemplate(classificationTemplateDto: ClassificationTemplateDto) : ClassificationTemplateDto?  {
        val localVariableConfig = createClassificationTemplateRequestConfig(classificationTemplateDto = classificationTemplateDto)

        return request<ClassificationTemplateDto, ClassificationTemplateDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createClassificationTemplate
    *
    * @param classificationTemplateDto  
    * @return RequestConfig
    */
    fun createClassificationTemplateRequestConfig(classificationTemplateDto: ClassificationTemplateDto) : RequestConfig<ClassificationTemplateDto> {
        val localVariableBody = classificationTemplateDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/classificationTemplate",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Delete classification Templates.
    * Response is a set containing the ID&#39;s of deleted classification Templates.
    * @param classificationTemplateIds  
    * @return kotlin.collections.List<DocIdentifier>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteClassificationTemplates(classificationTemplateIds: kotlin.String) : kotlin.collections.List<DocIdentifier>?  {
        val localVariableConfig = deleteClassificationTemplatesRequestConfig(classificationTemplateIds = classificationTemplateIds)

        return request<Unit, kotlin.collections.List<DocIdentifier>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation deleteClassificationTemplates
    *
    * @param classificationTemplateIds  
    * @return RequestConfig
    */
    fun deleteClassificationTemplatesRequestConfig(classificationTemplateIds: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.DELETE,
            path = "/rest/v1/classificationTemplate/{classificationTemplateIds}".replace("{"+"classificationTemplateIds"+"}", "$classificationTemplateIds"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * List classification Templates found By Healthcare Party and secret foreign keyelementIds.
    * Keys hast to delimited by coma
    * @param hcPartyId  
    * @param secretFKeys  
    * @return kotlin.collections.List<ClassificationTemplateDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun findClassificationTemplatesByHCPartyPatientForeignKeys(hcPartyId: kotlin.String, secretFKeys: kotlin.String) : kotlin.collections.List<ClassificationTemplateDto>?  {
        val localVariableConfig = findClassificationTemplatesByHCPartyPatientForeignKeysRequestConfig(hcPartyId = hcPartyId, secretFKeys = secretFKeys)

        return request<Unit, kotlin.collections.List<ClassificationTemplateDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findClassificationTemplatesByHCPartyPatientForeignKeys
    *
    * @param hcPartyId  
    * @param secretFKeys  
    * @return RequestConfig
    */
    fun findClassificationTemplatesByHCPartyPatientForeignKeysRequestConfig(hcPartyId: kotlin.String, secretFKeys: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                put("hcPartyId", listOf(hcPartyId.toString()))
                put("secretFKeys", listOf(secretFKeys.toString()))
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/classificationTemplate/byHcPartySecretForeignKeys",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Get a classification Template
    * 
    * @param classificationTemplateId  
    * @return ClassificationTemplateDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getClassificationTemplate(classificationTemplateId: kotlin.String) : ClassificationTemplateDto?  {
        val localVariableConfig = getClassificationTemplateRequestConfig(classificationTemplateId = classificationTemplateId)

        return request<Unit, ClassificationTemplateDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getClassificationTemplate
    *
    * @param classificationTemplateId  
    * @return RequestConfig
    */
    fun getClassificationTemplateRequestConfig(classificationTemplateId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/classificationTemplate/{classificationTemplateId}".replace("{"+"classificationTemplateId"+"}", "$classificationTemplateId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Get a list of classifications Templates
    * Ids are seperated by a coma
    * @param ids  
    * @return kotlin.collections.List<ClassificationTemplateDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getClassificationTemplateByIds(ids: kotlin.String) : kotlin.collections.List<ClassificationTemplateDto>?  {
        val localVariableConfig = getClassificationTemplateByIdsRequestConfig(ids = ids)

        return request<Unit, kotlin.collections.List<ClassificationTemplateDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getClassificationTemplateByIds
    *
    * @param ids  
    * @return RequestConfig
    */
    fun getClassificationTemplateByIdsRequestConfig(ids: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/classificationTemplate/byIds/{ids}".replace("{"+"ids"+"}", "$ids"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * List all classification templates with pagination
    * Returns a list of classification templates.
    * @param startKey A label (optional)
    * @param startDocumentId An classification template document ID (optional)
    * @param limit Number of rows (optional)
    * @return PaginatedListClassificationTemplateDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun listClassificationTemplates(startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : PaginatedListClassificationTemplateDto?  {
        val localVariableConfig = listClassificationTemplatesRequestConfig(startKey = startKey, startDocumentId = startDocumentId, limit = limit)

        return request<Unit, PaginatedListClassificationTemplateDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation listClassificationTemplates
    *
    * @param startKey A label (optional)
    * @param startDocumentId An classification template document ID (optional)
    * @param limit Number of rows (optional)
    * @return RequestConfig
    */
    fun listClassificationTemplatesRequestConfig(startKey: kotlin.String?, startDocumentId: kotlin.String?, limit: kotlin.Int?) : RequestConfig<Unit> {
        val localVariableBody = null
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
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/classificationTemplate",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Modify a classification Template
    * Returns the modified classification Template.
    * @param classificationTemplateDto  
    * @return ClassificationTemplateDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyClassificationTemplate(classificationTemplateDto: ClassificationTemplateDto) : ClassificationTemplateDto?  {
        val localVariableConfig = modifyClassificationTemplateRequestConfig(classificationTemplateDto = classificationTemplateDto)

        return request<ClassificationTemplateDto, ClassificationTemplateDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyClassificationTemplate
    *
    * @param classificationTemplateDto  
    * @return RequestConfig
    */
    fun modifyClassificationTemplateRequestConfig(classificationTemplateDto: ClassificationTemplateDto) : RequestConfig<ClassificationTemplateDto> {
        val localVariableBody = classificationTemplateDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/classificationTemplate",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Delegates a classification Template to a healthcare party
    * It delegates a classification Template to a healthcare party (By current healthcare party). Returns the element with new delegations.
    * @param classificationTemplateId  
    * @param delegationDto  
    * @return ClassificationTemplateDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun newClassificationTemplateDelegations(classificationTemplateId: kotlin.String, delegationDto: kotlin.collections.List<DelegationDto>) : ClassificationTemplateDto?  {
        val localVariableConfig = newClassificationTemplateDelegationsRequestConfig(classificationTemplateId = classificationTemplateId, delegationDto = delegationDto)

        return request<kotlin.collections.List<DelegationDto>, ClassificationTemplateDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation newClassificationTemplateDelegations
    *
    * @param classificationTemplateId  
    * @param delegationDto  
    * @return RequestConfig
    */
    fun newClassificationTemplateDelegationsRequestConfig(classificationTemplateId: kotlin.String, delegationDto: kotlin.collections.List<DelegationDto>) : RequestConfig<kotlin.collections.List<DelegationDto>> {
        val localVariableBody = delegationDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/classificationTemplate/{classificationTemplateId}/delegate".replace("{"+"classificationTemplateId"+"}", "$classificationTemplateId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
