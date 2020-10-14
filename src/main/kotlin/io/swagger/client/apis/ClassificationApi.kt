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

import io.swagger.client.models.ClassificationDto
import io.swagger.client.models.DelegationDto
import io.swagger.client.models.DocIdentifier
import io.swagger.client.models.IcureStubDto

import io.swagger.client.infrastructure.*

class ClassificationApi(basePath: kotlin.String = "https://kraken.icure.dev") : ApiClient(basePath) {

    /**
     * Create a classification with the current user
     * Returns an instance of created classification Template.
     * @param body  
     * @return ClassificationDto
     */
    @Suppress("UNCHECKED_CAST")
    fun createClassification(body: ClassificationDto): ClassificationDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/classification"
        )
        val response = request<ClassificationDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as ClassificationDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Delete classification Templates.
     * Response is a set containing the ID&#x27;s of deleted classification Templates.
     * @param classificationIds  
     * @return kotlin.Array<DocIdentifier>
     */
    @Suppress("UNCHECKED_CAST")
    fun deleteClassifications(classificationIds: kotlin.String): kotlin.Array<DocIdentifier> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.DELETE,
                "/rest/v1/classification/{classificationIds}".replace("{" + "classificationIds" + "}", "$classificationIds")
        )
        val response = request<kotlin.Array<DocIdentifier>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<DocIdentifier>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List classification Templates found By Healthcare Party and secret foreign keyelementIds.
     * Keys hast to delimited by coma
     * @param hcPartyId  
     * @param secretFKeys  
     * @return kotlin.Array<ClassificationDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun findClassificationsByHCPartyPatientForeignKeys(hcPartyId: kotlin.String, secretFKeys: kotlin.String): kotlin.Array<ClassificationDto> {
        val localVariableQuery: MultiValueMap = mapOf("hcPartyId" to listOf("$hcPartyId"), "secretFKeys" to listOf("$secretFKeys"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/classification/byHcPartySecretForeignKeys", query = localVariableQuery
        )
        val response = request<kotlin.Array<ClassificationDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<ClassificationDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get a classification Template
     * 
     * @param classificationId  
     * @return ClassificationDto
     */
    @Suppress("UNCHECKED_CAST")
    fun getClassification(classificationId: kotlin.String): ClassificationDto {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/classification/{classificationId}".replace("{" + "classificationId" + "}", "$classificationId")
        )
        val response = request<ClassificationDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as ClassificationDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get a list of classifications
     * Ids are seperated by a coma
     * @param ids  
     * @return kotlin.Array<ClassificationDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun getClassificationByHcPartyId(ids: kotlin.String): kotlin.Array<ClassificationDto> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/classification/byIds/{ids}".replace("{" + "ids" + "}", "$ids")
        )
        val response = request<kotlin.Array<ClassificationDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<ClassificationDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Modify a classification Template
     * Returns the modified classification Template.
     * @param body  
     * @return ClassificationDto
     */
    @Suppress("UNCHECKED_CAST")
    fun modifyClassification(body: ClassificationDto): ClassificationDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.PUT,
                "/rest/v1/classification"
        )
        val response = request<ClassificationDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as ClassificationDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Delegates a classification to a healthcare party
     * It delegates a classification to a healthcare party (By current healthcare party). Returns the element with new delegations.
     * @param body  
     * @param classificationId  
     * @return ClassificationDto
     */
    @Suppress("UNCHECKED_CAST")
    fun newClassificationDelegations(body: kotlin.Array<DelegationDto>, classificationId: kotlin.String): ClassificationDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/classification/{classificationId}/delegate".replace("{" + "classificationId" + "}", "$classificationId")
        )
        val response = request<ClassificationDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as ClassificationDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Update delegations in classification
     * Keys must be delimited by coma
     * @param body  
     * @return kotlin.Array<IcureStubDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun setClassificationsDelegations(body: kotlin.Array<IcureStubDto>): kotlin.Array<IcureStubDto> {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/classification/delegations"
        )
        val response = request<kotlin.Array<IcureStubDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<IcureStubDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
}
