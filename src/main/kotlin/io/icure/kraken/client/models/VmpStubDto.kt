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
package io.icure.kraken.client.models

import io.icure.kraken.client.models.SamTextDto
import io.icure.kraken.client.models.VmpGroupStubDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param id 
 * @param code 
 * @param vmpGroup 
 * @param name 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class VmpStubDto (

    @field:JsonProperty("id")
    val id: kotlin.String,

    @field:JsonProperty("code")
    val code: kotlin.String? = null,

    @field:JsonProperty("vmpGroup")
    val vmpGroup: VmpGroupStubDto? = null,

    @field:JsonProperty("name")
    val name: SamTextDto? = null

)

