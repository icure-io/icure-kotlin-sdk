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
import io.icure.kraken.client.models.ReceiptDto

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
class ReceiptApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Creates a receipt
    * 
    * @param receiptDto  
    * @return ReceiptDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun createReceipt(receiptDto: ReceiptDto) : ReceiptDto?  {
        val localVariableConfig = createReceiptRequestConfig(receiptDto = receiptDto)

        return request<ReceiptDto, ReceiptDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createReceipt
    *
    * @param receiptDto  
    * @return RequestConfig
    */
    fun createReceiptRequestConfig(receiptDto: ReceiptDto) : RequestConfig<ReceiptDto> {
        val localVariableBody = receiptDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/receipt",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Deletes a receipt
    * 
    * @param receiptIds  
    * @return kotlin.collections.List<DocIdentifier>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun deleteReceipt(receiptIds: kotlin.String) : kotlin.collections.List<DocIdentifier>?  {
        val localVariableConfig = deleteReceiptRequestConfig(receiptIds = receiptIds)

        return request<Unit, kotlin.collections.List<DocIdentifier>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation deleteReceipt
    *
    * @param receiptIds  
    * @return RequestConfig
    */
    fun deleteReceiptRequestConfig(receiptIds: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.DELETE,
            path = "/rest/v1/receipt/{receiptIds}".replace("{"+"receiptIds"+"}", "$receiptIds"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets a receipt
    * 
    * @param receiptId  
    * @return ReceiptDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getReceipt(receiptId: kotlin.String) : ReceiptDto?  {
        val localVariableConfig = getReceiptRequestConfig(receiptId = receiptId)

        return request<Unit, ReceiptDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getReceipt
    *
    * @param receiptId  
    * @return RequestConfig
    */
    fun getReceiptRequestConfig(receiptId: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/receipt/{receiptId}".replace("{"+"receiptId"+"}", "$receiptId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Get an attachment
    * 
    * @param receiptId  
    * @param attachmentId  
    * @param enckeys  
    * @return java.io.File
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun getReceiptAttachment(receiptId: kotlin.String, attachmentId: kotlin.String, enckeys: kotlin.String) : java.io.File?  {
        val localVariableConfig = getReceiptAttachmentRequestConfig(receiptId = receiptId, attachmentId = attachmentId, enckeys = enckeys)

        return request<Unit, java.io.File>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation getReceiptAttachment
    *
    * @param receiptId  
    * @param attachmentId  
    * @param enckeys  
    * @return RequestConfig
    */
    fun getReceiptAttachmentRequestConfig(receiptId: kotlin.String, attachmentId: kotlin.String, enckeys: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                put("enckeys", listOf(enckeys.toString()))
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/receipt/{receiptId}/attachment/{attachmentId}".replace("{"+"receiptId"+"}", "$receiptId").replace("{"+"attachmentId"+"}", "$attachmentId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Gets a receipt
    * 
    * @param ref  
    * @return kotlin.collections.List<ReceiptDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun listByReference(ref: kotlin.String) : kotlin.collections.List<ReceiptDto>?  {
        val localVariableConfig = listByReferenceRequestConfig(ref = ref)

        return request<Unit, kotlin.collections.List<ReceiptDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation listByReference
    *
    * @param ref  
    * @return RequestConfig
    */
    fun listByReferenceRequestConfig(ref: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/receipt/byref/{ref}".replace("{"+"ref"+"}", "$ref"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Updates a receipt
    * 
    * @param receiptDto  
    * @return ReceiptDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun modifyReceipt(receiptDto: ReceiptDto) : ReceiptDto?  {
        val localVariableConfig = modifyReceiptRequestConfig(receiptDto = receiptDto)

        return request<ReceiptDto, ReceiptDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation modifyReceipt
    *
    * @param receiptDto  
    * @return RequestConfig
    */
    fun modifyReceiptRequestConfig(receiptDto: ReceiptDto) : RequestConfig<ReceiptDto> {
        val localVariableBody = receiptDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/receipt",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Creates a receipt&#39;s attachment
    * 
    * @param receiptId  
    * @param blobType  
    * @param body  
    * @param enckeys  (optional)
    * @return ReceiptDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun setReceiptAttachment(receiptId: kotlin.String, blobType: kotlin.String, body: kotlin.ByteArray, enckeys: kotlin.String?) : ReceiptDto?  {
        val localVariableConfig = setReceiptAttachmentRequestConfig(receiptId = receiptId, blobType = blobType, body = body, enckeys = enckeys)

        return request<kotlin.ByteArray, ReceiptDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation setReceiptAttachment
    *
    * @param receiptId  
    * @param blobType  
    * @param body  
    * @param enckeys  (optional)
    * @return RequestConfig
    */
    fun setReceiptAttachmentRequestConfig(receiptId: kotlin.String, blobType: kotlin.String, body: kotlin.ByteArray, enckeys: kotlin.String?) : RequestConfig<kotlin.ByteArray> {
        val localVariableBody = body
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (enckeys != null) {
                    put("enckeys", listOf(enckeys.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/receipt/{receiptId}/attachment/{blobType}".replace("{"+"receiptId"+"}", "$receiptId").replace("{"+"blobType"+"}", "$blobType"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
