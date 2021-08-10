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
package io.icure.kraken.client.models


import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param user 
 * @param password 
 * @param serverUrl 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class MikronoCredentialsDto (

    @field:JsonProperty("user")
    val user: kotlin.String? = null,

    @field:JsonProperty("password")
    val password: kotlin.String? = null,

    @field:JsonProperty("serverUrl")
    val serverUrl: kotlin.String? = null

)

