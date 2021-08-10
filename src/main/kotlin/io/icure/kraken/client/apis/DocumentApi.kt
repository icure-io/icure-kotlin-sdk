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
import io.icure.kraken.client.models.DocIdentifier
import io.icure.kraken.client.models.DocumentDto
import io.icure.kraken.client.models.IcureStubDto
import io.icure.kraken.client.models.ListOfIdsDto

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
class DocumentApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient()) : ApiClient(basePath, webClient) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Creates a document
    * 
    * @param documentDto  
    * @return DocumentDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createDocument(documentDto: DocumentDto) : DocumentDto?  {
        val localVariableConfig = createDocumentRequestConfig(documentDto = documentDto)

        return request<DocumentDto, DocumentDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createDocument
    *
    * @param documentDto  
    * @return RequestConfig
    */
    fun createDocumentRequestConfig(documentDto: DocumentDto) : RequestConfig<DocumentDto> {
        val localVariableBody = documentDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/document",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Deletes a document&#39;s attachment
    * 
    * @param documentId  
    * @return DocumentDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteAttachment(documentId: kotlin.String) : DocumentDto?  {
        val localVariableConfig = deleteAttachmentRequestConfig(documentId = documentId)

        return request<Unit, DocumentDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation deleteAttachment
    *
    * @param documentId  
    * @return RequestConfig
    */
    fun deleteAttachmentRequestConfig(documentId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.DELETE,
            path = "/rest/v1/document/{documentId}/attachment".replace("{"+"documentId"+"}", "$documentId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Deletes a document
    * 
    * @param documentIds  
    * @return kotlin.collections.List<DocIdentifier>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteDocument(documentIds: kotlin.String) : kotlin.collections.List<DocIdentifier>?  {
        val localVariableConfig = deleteDocumentRequestConfig(documentIds = documentIds)

        return request<Unit, kotlin.collections.List<DocIdentifier>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation deleteDocument
    *
    * @param documentIds  
    * @return RequestConfig
    */
    fun deleteDocumentRequestConfig(documentIds: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.DELETE,
            path = "/rest/v1/document/{documentIds}".replace("{"+"documentIds"+"}", "$documentIds"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * List documents found By type, By Healthcare Party and secret foreign keys.
    * Keys must be delimited by coma
    * @param documentTypeCode  
    * @param hcPartyId  
    * @param secretFKeys  
    * @return kotlin.collections.List<DocumentDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun findByTypeHCPartyMessageSecretFKeys(documentTypeCode: kotlin.String, hcPartyId: kotlin.String, secretFKeys: kotlin.String) : kotlin.collections.List<DocumentDto>?  {
        val localVariableConfig = findByTypeHCPartyMessageSecretFKeysRequestConfig(documentTypeCode = documentTypeCode, hcPartyId = hcPartyId, secretFKeys = secretFKeys)

        return request<Unit, kotlin.collections.List<DocumentDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findByTypeHCPartyMessageSecretFKeys
    *
    * @param documentTypeCode  
    * @param hcPartyId  
    * @param secretFKeys  
    * @return RequestConfig
    */
    fun findByTypeHCPartyMessageSecretFKeysRequestConfig(documentTypeCode: kotlin.String, hcPartyId: kotlin.String, secretFKeys: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                put("documentTypeCode", listOf(documentTypeCode.toString()))
                put("hcPartyId", listOf(hcPartyId.toString()))
                put("secretFKeys", listOf(secretFKeys.toString()))
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/document/byTypeHcPartySecretForeignKeys",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * List documents found By Healthcare Party and secret foreign keys.
    * Keys must be delimited by coma
    * @param hcPartyId  
    * @param secretFKeys  
    * @return kotlin.collections.List<DocumentDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun findDocumentsByHCPartyPatientForeignKeys(hcPartyId: kotlin.String, secretFKeys: kotlin.String) : kotlin.collections.List<DocumentDto>?  {
        val localVariableConfig = findDocumentsByHCPartyPatientForeignKeysRequestConfig(hcPartyId = hcPartyId, secretFKeys = secretFKeys)

        return request<Unit, kotlin.collections.List<DocumentDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findDocumentsByHCPartyPatientForeignKeys
    *
    * @param hcPartyId  
    * @param secretFKeys  
    * @return RequestConfig
    */
    fun findDocumentsByHCPartyPatientForeignKeysRequestConfig(hcPartyId: kotlin.String, secretFKeys: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                put("hcPartyId", listOf(hcPartyId.toString()))
                put("secretFKeys", listOf(secretFKeys.toString()))
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/document/byHcPartySecretForeignKeys",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * List documents with no delegation
    * Keys must be delimited by coma
    * @param limit  (optional)
    * @return kotlin.collections.List<DocumentDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun findWithoutDelegation(limit: kotlin.Int?) : kotlin.collections.List<DocumentDto>?  {
        val localVariableConfig = findWithoutDelegationRequestConfig(limit = limit)

        return request<Unit, kotlin.collections.List<DocumentDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation findWithoutDelegation
    *
    * @param limit  (optional)
    * @return RequestConfig
    */
    fun findWithoutDelegationRequestConfig(limit: kotlin.Int?) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (limit != null) {
                    put("limit", listOf(limit.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/document/woDelegation",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets a document
    * 
    * @param documentId  
    * @return DocumentDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getDocument(documentId: kotlin.String) : DocumentDto?  {
        val localVariableConfig = getDocumentRequestConfig(documentId = documentId)

        return request<Unit, DocumentDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getDocument
    *
    * @param documentId  
    * @return RequestConfig
    */
    fun getDocumentRequestConfig(documentId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/document/{documentId}".replace("{"+"documentId"+"}", "$documentId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Load document&#39;s attachment
    * 
    * @param documentId  
    * @param attachmentId  
    * @param enckeys  (optional)
    * @param fileName  (optional)
    * @return java.io.File
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getDocumentAttachment(documentId: kotlin.String, attachmentId: kotlin.String, enckeys: kotlin.String?, fileName: kotlin.String?) : java.io.File?  {
        val localVariableConfig = getDocumentAttachmentRequestConfig(documentId = documentId, attachmentId = attachmentId, enckeys = enckeys, fileName = fileName)

        return request<Unit, java.io.File>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getDocumentAttachment
    *
    * @param documentId  
    * @param attachmentId  
    * @param enckeys  (optional)
    * @param fileName  (optional)
    * @return RequestConfig
    */
    fun getDocumentAttachmentRequestConfig(documentId: kotlin.String, attachmentId: kotlin.String, enckeys: kotlin.String?, fileName: kotlin.String?) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (enckeys != null) {
                    put("enckeys", listOf(enckeys.toString()))
                }
                if (fileName != null) {
                    put("fileName", listOf(fileName.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/document/{documentId}/attachment/{attachmentId}".replace("{"+"documentId"+"}", "$documentId").replace("{"+"attachmentId"+"}", "$attachmentId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets a document
    * 
    * @param externalUuid  
    * @return DocumentDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getDocumentByExternalUuid(externalUuid: kotlin.String) : DocumentDto?  {
        val localVariableConfig = getDocumentByExternalUuidRequestConfig(externalUuid = externalUuid)

        return request<Unit, DocumentDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getDocumentByExternalUuid
    *
    * @param externalUuid  
    * @return RequestConfig
    */
    fun getDocumentByExternalUuidRequestConfig(externalUuid: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/document/externaluuid/{externalUuid}".replace("{"+"externalUuid"+"}", "$externalUuid"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets a document
    * 
    * @param listOfIdsDto  
    * @return kotlin.collections.List<DocumentDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getDocuments(listOfIdsDto: ListOfIdsDto) : kotlin.collections.List<DocumentDto>?  {
        val localVariableConfig = getDocumentsRequestConfig(listOfIdsDto = listOfIdsDto)

        return request<ListOfIdsDto, kotlin.collections.List<DocumentDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getDocuments
    *
    * @param listOfIdsDto  
    * @return RequestConfig
    */
    fun getDocumentsRequestConfig(listOfIdsDto: ListOfIdsDto) : RequestConfig<ListOfIdsDto> {
        val localVariableBody = listOfIdsDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/document/batch",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Get all documents with externalUuid
    * 
    * @param externalUuid  
    * @return kotlin.collections.List<DocumentDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getDocumentsByExternalUuid(externalUuid: kotlin.String) : kotlin.collections.List<DocumentDto>?  {
        val localVariableConfig = getDocumentsByExternalUuidRequestConfig(externalUuid = externalUuid)

        return request<Unit, kotlin.collections.List<DocumentDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getDocumentsByExternalUuid
    *
    * @param externalUuid  
    * @return RequestConfig
    */
    fun getDocumentsByExternalUuidRequestConfig(externalUuid: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/document/externaluuid/{externalUuid}/all".replace("{"+"externalUuid"+"}", "$externalUuid"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Updates a document
    * 
    * @param documentDto  
    * @return DocumentDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyDocument(documentDto: DocumentDto) : DocumentDto?  {
        val localVariableConfig = modifyDocumentRequestConfig(documentDto = documentDto)

        return request<DocumentDto, DocumentDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyDocument
    *
    * @param documentDto  
    * @return RequestConfig
    */
    fun modifyDocumentRequestConfig(documentDto: DocumentDto) : RequestConfig<DocumentDto> {
        val localVariableBody = documentDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/document",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Updates a batch of documents
    * Returns the modified documents.
    * @param documentDto  
    * @return kotlin.collections.List<DocumentDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyDocuments(documentDto: kotlin.collections.List<DocumentDto>) : kotlin.collections.List<DocumentDto>?  {
        val localVariableConfig = modifyDocumentsRequestConfig(documentDto = documentDto)

        return request<kotlin.collections.List<DocumentDto>, kotlin.collections.List<DocumentDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyDocuments
    *
    * @param documentDto  
    * @return RequestConfig
    */
    fun modifyDocumentsRequestConfig(documentDto: kotlin.collections.List<DocumentDto>) : RequestConfig<kotlin.collections.List<DocumentDto>> {
        val localVariableBody = documentDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/document/batch",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Creates a document&#39;s attachment
    * 
    * @param documentId  
    * @param requestBody  
    * @param enckeys  (optional)
    * @return DocumentDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun setDocumentAttachment(documentId: kotlin.String, requestBody: kotlin.collections.List<kotlin.ByteArray>, enckeys: kotlin.String?) : DocumentDto?  {
        val localVariableConfig = setDocumentAttachmentRequestConfig(documentId = documentId, requestBody = requestBody, enckeys = enckeys)

        return request<kotlin.collections.List<kotlin.ByteArray>, DocumentDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation setDocumentAttachment
    *
    * @param documentId  
    * @param requestBody  
    * @param enckeys  (optional)
    * @return RequestConfig
    */
    fun setDocumentAttachmentRequestConfig(documentId: kotlin.String, requestBody: kotlin.collections.List<kotlin.ByteArray>, enckeys: kotlin.String?) : RequestConfig<kotlin.collections.List<kotlin.ByteArray>> {
        val localVariableBody = requestBody
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (enckeys != null) {
                    put("enckeys", listOf(enckeys.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/document/{documentId}/attachment".replace("{"+"documentId"+"}", "$documentId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Creates a document&#39;s attachment
    * 
    * @param documentId  
    * @param enckeys  (optional)
    * @return DocumentDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun setDocumentAttachmentMulti(documentId: kotlin.String, enckeys: kotlin.String?) : DocumentDto?  {
        val localVariableConfig = setDocumentAttachmentMultiRequestConfig(documentId = documentId, enckeys = enckeys)

        return request<Unit, DocumentDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation setDocumentAttachmentMulti
    *
    * @param documentId  
    * @param enckeys  (optional)
    * @return RequestConfig
    */
    fun setDocumentAttachmentMultiRequestConfig(documentId: kotlin.String, enckeys: kotlin.String?) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (enckeys != null) {
                    put("enckeys", listOf(enckeys.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/document/{documentId}/attachment/multipart".replace("{"+"documentId"+"}", "$documentId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Update delegations in healthElements.
    * Keys must be delimited by coma
    * @param icureStubDto  
    * @return kotlin.collections.List<IcureStubDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun setDocumentsDelegations(icureStubDto: kotlin.collections.List<IcureStubDto>) : kotlin.collections.List<IcureStubDto>?  {
        val localVariableConfig = setDocumentsDelegationsRequestConfig(icureStubDto = icureStubDto)

        return request<kotlin.collections.List<IcureStubDto>, kotlin.collections.List<IcureStubDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation setDocumentsDelegations
    *
    * @param icureStubDto  
    * @return RequestConfig
    */
    fun setDocumentsDelegationsRequestConfig(icureStubDto: kotlin.collections.List<IcureStubDto>) : RequestConfig<kotlin.collections.List<IcureStubDto>> {
        val localVariableBody = icureStubDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/document/delegations",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Creates a document&#39;s attachment
    * 
    * @param documentId  
    * @param requestBody  
    * @param enckeys  (optional)
    * @return DocumentDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun setSafeDocumentAttachment(documentId: kotlin.String, requestBody: kotlin.collections.List<kotlin.ByteArray>, enckeys: kotlin.String?) : DocumentDto?  {
        val localVariableConfig = setSafeDocumentAttachmentRequestConfig(documentId = documentId, requestBody = requestBody, enckeys = enckeys)

        return request<kotlin.collections.List<kotlin.ByteArray>, DocumentDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation setSafeDocumentAttachment
    *
    * @param documentId  
    * @param requestBody  
    * @param enckeys  (optional)
    * @return RequestConfig
    */
    fun setSafeDocumentAttachmentRequestConfig(documentId: kotlin.String, requestBody: kotlin.collections.List<kotlin.ByteArray>, enckeys: kotlin.String?) : RequestConfig<kotlin.collections.List<kotlin.ByteArray>> {
        val localVariableBody = requestBody
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                put("documentId", listOf(documentId.toString()))
                if (enckeys != null) {
                    put("enckeys", listOf(enckeys.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/document/attachment",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
