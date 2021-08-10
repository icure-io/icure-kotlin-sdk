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
 * When a document needs to be encrypted, the responsible generates a cryptographically random master key (different from the delegation key, never to appear in clear anywhere in the db. He/she encrypts it using his own AES exchange key and stores it as a delegation
 *
 * @param tags 
 * @param owner 
 * @param delegatedTo 
 * @param key 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class DelegationDto (

    @field:JsonProperty("tags")
    val tags: kotlin.collections.List<kotlin.String>,

    @field:JsonProperty("owner")
    val owner: kotlin.String? = null,

    @field:JsonProperty("delegatedTo")
    val delegatedTo: kotlin.String? = null,

    @field:JsonProperty("key")
    val key: kotlin.String? = null

)

