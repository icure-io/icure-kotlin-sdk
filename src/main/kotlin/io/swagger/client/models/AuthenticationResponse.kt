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
package io.swagger.client.models


/**
 * 
 * @param healthcarePartyId 
 * @param reason 
 * @param successful 
 * @param username 
 */
data class AuthenticationResponse (
    val successful: kotlin.Boolean
,
    val healthcarePartyId: kotlin.String? = null,
    val reason: kotlin.String? = null,
    val username: kotlin.String? = null
) {
}