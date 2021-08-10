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
import io.icure.kraken.client.models.AuthenticationResponse
import io.icure.kraken.client.models.WebSession

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
class AuthApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient()) : ApiClient(basePath, webClient) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * login
    * Login using username and password
    * @param webSession  (optional)
    * @return AuthenticationResponse
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun login(webSession: WebSession?) : AuthenticationResponse?  {
        val localVariableConfig = loginRequestConfig(webSession = webSession)

        return request<WebSession, AuthenticationResponse>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation login
    *
    * @param webSession  (optional)
    * @return RequestConfig
    */
    fun loginRequestConfig(webSession: WebSession?) : RequestConfig<WebSession> {
        val localVariableBody = webSession
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/auth/login",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * logout
    * Logout
    * @return AuthenticationResponse
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun logout() : AuthenticationResponse?  {
        val localVariableConfig = logoutRequestConfig()

        return request<Unit, AuthenticationResponse>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation logout
    *
    * @return RequestConfig
    */
    fun logoutRequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/auth/logout",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * logout
    * Logout
    * @return AuthenticationResponse
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun logoutPost() : AuthenticationResponse?  {
        val localVariableConfig = logoutPostRequestConfig()

        return request<Unit, AuthenticationResponse>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation logoutPost
    *
    * @return RequestConfig
    */
    fun logoutPostRequestConfig() : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/auth/logout",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * token
    * Get token for subsequent operation
    * @param method  
    * @param path  
    * @return kotlin.String
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    suspend fun token(method: kotlin.String, path: kotlin.String) : kotlin.String?  {
        val localVariableConfig = tokenRequestConfig(method = method, path = path)

        return request<Unit, kotlin.String>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation token
    *
    * @param method  
    * @param path  
    * @return RequestConfig
    */
    fun tokenRequestConfig(method: kotlin.String, path: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/auth/token/{method}/{path}".replace("{"+"method"+"}", "$method").replace("{"+"path"+"}", "$path"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
