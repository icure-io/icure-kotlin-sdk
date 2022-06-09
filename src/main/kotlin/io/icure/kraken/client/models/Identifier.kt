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

import io.icure.kraken.client.models.CodeStub

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param id 
 * @param assigner 
 * @param start 
 * @param end 
 * @param system 
 * @param type 
 * @param use 
 * @param `value` 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class Identifier (

    @field:JsonProperty("id")
    val id: kotlin.String? = null,

    @field:JsonProperty("assigner")
    val assigner: kotlin.String? = null,

    @field:JsonProperty("start")
    val start: kotlin.String? = null,

    @field:JsonProperty("end")
    val end: kotlin.String? = null,

    @field:JsonProperty("system")
    val system: kotlin.String? = null,

    @field:JsonProperty("type")
    val type: CodeStub? = null,

    @field:JsonProperty("use")
    val use: kotlin.String? = null,

    @field:JsonProperty("value")
    val `value`: kotlin.String? = null

)
