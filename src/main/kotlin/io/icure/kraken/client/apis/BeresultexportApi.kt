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
class BeresultexportApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Export data
    * 
    * @param fromHcpId  
    * @param toHcpId  
    * @param patId  
    * @param date  
    * @param ref  
    * @param ioIcureKrakenClientInfrastructureByteArrayWrapper  
    * @return kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun exportHealthOne(fromHcpId: kotlin.String, toHcpId: kotlin.String, patId: kotlin.String, date: kotlin.Long, ref: kotlin.String, ioIcureKrakenClientInfrastructureByteArrayWrapper: kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>) : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer>  {
        val localVariableConfig = exportHealthOneRequestConfig(fromHcpId = fromHcpId, toHcpId = toHcpId, patId = patId, date = date, ref = ref, ioIcureKrakenClientInfrastructureByteArrayWrapper = ioIcureKrakenClientInfrastructureByteArrayWrapper)

        return request<kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>, kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation exportHealthOne
    *
    * @param fromHcpId  
    * @param toHcpId  
    * @param patId  
    * @param date  
    * @param ref  
    * @param ioIcureKrakenClientInfrastructureByteArrayWrapper  
    * @return RequestConfig
    */
    fun exportHealthOneRequestConfig(fromHcpId: kotlin.String, toHcpId: kotlin.String, patId: kotlin.String, date: kotlin.Long, ref: kotlin.String, ioIcureKrakenClientInfrastructureByteArrayWrapper: kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>) : RequestConfig<kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>> {
        // val localVariableBody = ioIcureKrakenClientInfrastructureByteArrayWrapper
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/octet-stream")
        localVariableHeaders["Accept"] = "application/octet-stream"
        val localVariableBody = ioIcureKrakenClientInfrastructureByteArrayWrapper

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/be_result_export/hl1/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref}".replace("{"+"fromHcpId"+"}", "${URLEncoder.encode(fromHcpId.toString(), Charsets.UTF_8)}").replace("{"+"toHcpId"+"}", "${URLEncoder.encode(toHcpId.toString(), Charsets.UTF_8)}").replace("{"+"patId"+"}", "${URLEncoder.encode(patId.toString(), Charsets.UTF_8)}").replace("{"+"date"+"}", "${URLEncoder.encode(date.toString(), Charsets.UTF_8)}").replace("{"+"ref"+"}", "${URLEncoder.encode(ref.toString(), Charsets.UTF_8)}"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Export data
    * 
    * @param fromHcpId  
    * @param toHcpId  
    * @param patId  
    * @param date  
    * @param ref  
    * @param ioIcureKrakenClientInfrastructureByteArrayWrapper  
    * @param mimeType  (optional)
    * @return kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun exportKmehrReport(fromHcpId: kotlin.String, toHcpId: kotlin.String, patId: kotlin.String, date: kotlin.Long, ref: kotlin.String, ioIcureKrakenClientInfrastructureByteArrayWrapper: kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>, mimeType: kotlin.Boolean?) : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer>  {
        val localVariableConfig = exportKmehrReportRequestConfig(fromHcpId = fromHcpId, toHcpId = toHcpId, patId = patId, date = date, ref = ref, ioIcureKrakenClientInfrastructureByteArrayWrapper = ioIcureKrakenClientInfrastructureByteArrayWrapper, mimeType = mimeType)

        return request<kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>, kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation exportKmehrReport
    *
    * @param fromHcpId  
    * @param toHcpId  
    * @param patId  
    * @param date  
    * @param ref  
    * @param ioIcureKrakenClientInfrastructureByteArrayWrapper  
    * @param mimeType  (optional)
    * @return RequestConfig
    */
    fun exportKmehrReportRequestConfig(fromHcpId: kotlin.String, toHcpId: kotlin.String, patId: kotlin.String, date: kotlin.Long, ref: kotlin.String, ioIcureKrakenClientInfrastructureByteArrayWrapper: kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>, mimeType: kotlin.Boolean?) : RequestConfig<kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>> {
        // val localVariableBody = ioIcureKrakenClientInfrastructureByteArrayWrapper
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (mimeType != null) {
                    put("mimeType", listOf(mimeType.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/octet-stream")
        localVariableHeaders["Accept"] = "application/octet-stream"
        val localVariableBody = ioIcureKrakenClientInfrastructureByteArrayWrapper

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/be_result_export/kmehrreport/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref}".replace("{"+"fromHcpId"+"}", "${URLEncoder.encode(fromHcpId.toString(), Charsets.UTF_8)}").replace("{"+"toHcpId"+"}", "${URLEncoder.encode(toHcpId.toString(), Charsets.UTF_8)}").replace("{"+"patId"+"}", "${URLEncoder.encode(patId.toString(), Charsets.UTF_8)}").replace("{"+"date"+"}", "${URLEncoder.encode(date.toString(), Charsets.UTF_8)}").replace("{"+"ref"+"}", "${URLEncoder.encode(ref.toString(), Charsets.UTF_8)}"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

    /**
    * Export data
    * 
    * @param fromHcpId  
    * @param toHcpId  
    * @param patId  
    * @param date  
    * @param ref  
    * @param ioIcureKrakenClientInfrastructureByteArrayWrapper  
    * @return kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun exportMedidoc(fromHcpId: kotlin.String, toHcpId: kotlin.String, patId: kotlin.String, date: kotlin.Long, ref: kotlin.String, ioIcureKrakenClientInfrastructureByteArrayWrapper: kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>) : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer>  {
        val localVariableConfig = exportMedidocRequestConfig(fromHcpId = fromHcpId, toHcpId = toHcpId, patId = patId, date = date, ref = ref, ioIcureKrakenClientInfrastructureByteArrayWrapper = ioIcureKrakenClientInfrastructureByteArrayWrapper)

        return request<kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>, kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer>>(
            localVariableConfig
        )!!
    }
    /**
    * To obtain the request config of the operation exportMedidoc
    *
    * @param fromHcpId  
    * @param toHcpId  
    * @param patId  
    * @param date  
    * @param ref  
    * @param ioIcureKrakenClientInfrastructureByteArrayWrapper  
    * @return RequestConfig
    */
    fun exportMedidocRequestConfig(fromHcpId: kotlin.String, toHcpId: kotlin.String, patId: kotlin.String, date: kotlin.Long, ref: kotlin.String, ioIcureKrakenClientInfrastructureByteArrayWrapper: kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>) : RequestConfig<kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>> {
        // val localVariableBody = ioIcureKrakenClientInfrastructureByteArrayWrapper
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf("Content-Type" to "application/octet-stream")
        localVariableHeaders["Accept"] = "application/octet-stream"
        val localVariableBody = ioIcureKrakenClientInfrastructureByteArrayWrapper

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v2/be_result_export/medidoc/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref}".replace("{"+"fromHcpId"+"}", "${URLEncoder.encode(fromHcpId.toString(), Charsets.UTF_8)}").replace("{"+"toHcpId"+"}", "${URLEncoder.encode(toHcpId.toString(), Charsets.UTF_8)}").replace("{"+"patId"+"}", "${URLEncoder.encode(patId.toString(), Charsets.UTF_8)}").replace("{"+"date"+"}", "${URLEncoder.encode(date.toString(), Charsets.UTF_8)}").replace("{"+"ref"+"}", "${URLEncoder.encode(ref.toString(), Charsets.UTF_8)}"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody        )
    }

}
