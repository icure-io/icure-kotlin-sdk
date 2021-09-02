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
class PubsubApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Offer auth data on secret bucket
    * Offer auth data on previously agreed on secret bucket, data should be encrypted
    * @param bucket  
    * @param body  
    * @return kotlin.collections.Map<kotlin.String, kotlin.Boolean>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun offerAuth(bucket: kotlin.String, body: java.io.File) : kotlin.collections.Map<kotlin.String, kotlin.Boolean>  {
        val localVariableConfig = offerAuthRequestConfig(bucket = bucket, body = body)

        return request<java.io.File, kotlin.collections.Map<kotlin.String, kotlin.Boolean>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation offerAuth
    *
    * @param bucket  
    * @param body  
    * @return RequestConfig
    */
    fun offerAuthRequestConfig(bucket: kotlin.String, body: java.io.File) : RequestConfig<java.io.File> {
        val localVariableBody = body
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/pubsub/auth/{bucket}".replace("{"+"bucket"+"}", "$bucket"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * publish data
    * Publish value with key
    * @param key  
    * @param body  
    * @return kotlin.collections.Map<kotlin.String, kotlin.Boolean>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun pub(key: kotlin.String, body: java.io.File) : kotlin.collections.Map<kotlin.String, kotlin.Boolean>  {
        val localVariableConfig = pubRequestConfig(key = key, body = body)

        return request<java.io.File, kotlin.collections.Map<kotlin.String, kotlin.Boolean>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation pub
    *
    * @param key  
    * @param body  
    * @return RequestConfig
    */
    fun pubRequestConfig(key: kotlin.String, body: java.io.File) : RequestConfig<java.io.File> {
        val localVariableBody = body
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/pubsub/pub/{key}".replace("{"+"key"+"}", "$key"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Recover auth data from secret bucket
    * Recover auth data from bucket, data should be encrypted
    * @param bucket  
    * @return java.io.File
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun recoverAuth(bucket: kotlin.String) : java.io.File  {
        val localVariableConfig = recoverAuthRequestConfig(bucket = bucket)

        return request<Unit, java.io.File>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation recoverAuth
    *
    * @param bucket  
    * @return RequestConfig
    */
    fun recoverAuthRequestConfig(bucket: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/pubsub/auth/recover/{bucket}".replace("{"+"bucket"+"}", "$bucket"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * subscribe to data
    * Try to get published data
    * @param key  
    * @return java.io.File
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun sub(key: kotlin.String) : java.io.File  {
        val localVariableConfig = subRequestConfig(key = key)

        return request<Unit, java.io.File>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation sub
    *
    * @param key  
    * @return RequestConfig
    */
    fun subRequestConfig(key: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/pubsub/sub/{key}".replace("{"+"key"+"}", "$key"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
