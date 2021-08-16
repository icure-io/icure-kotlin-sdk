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
package io.icure.kraken.client.models


import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param successful 
 * @param healthcarePartyId 
 * @param reason 
 * @param username 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class AuthenticationResponse (

    @field:JsonProperty("successful")
    val successful: kotlin.Boolean,

    @field:JsonProperty("healthcarePartyId")
    val healthcarePartyId: kotlin.String? = null,

    @field:JsonProperty("reason")
    val reason: kotlin.String? = null,

    @field:JsonProperty("username")
    val username: kotlin.String? = null

)

