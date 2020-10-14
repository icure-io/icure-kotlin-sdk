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

import io.swagger.client.models.AuthenticationResponse
import io.swagger.client.models.WebSession

import io.swagger.client.infrastructure.*

class AuthApi(basePath: kotlin.String = "https://kraken.icure.dev") : ApiClient(basePath) {

    /**
     * login
     * Login using username and password
     * @param body  (optional)
     * @return AuthenticationResponse
     */
    @Suppress("UNCHECKED_CAST")
    fun login(body: WebSession? = null): AuthenticationResponse {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/auth/login"
        )
        val response = request<AuthenticationResponse>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as AuthenticationResponse
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * logout
     * Logout
     * @return AuthenticationResponse
     */
    @Suppress("UNCHECKED_CAST")
    fun logout(): AuthenticationResponse {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/auth/logout"
        )
        val response = request<AuthenticationResponse>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as AuthenticationResponse
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * logout
     * Logout
     * @return AuthenticationResponse
     */
    @Suppress("UNCHECKED_CAST")
    fun logoutPost(): AuthenticationResponse {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/auth/logout"
        )
        val response = request<AuthenticationResponse>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as AuthenticationResponse
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * token
     * Get token for subsequent operation
     * @param method  
     * @param path  
     * @return kotlin.String
     */
    @Suppress("UNCHECKED_CAST")
    fun token(method: kotlin.String, path: kotlin.String): kotlin.String {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/auth/token/{method}/{path}".replace("{" + "method" + "}", "$method").replace("{" + "path" + "}", "$path")
        )
        val response = request<kotlin.String>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.String
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
}
