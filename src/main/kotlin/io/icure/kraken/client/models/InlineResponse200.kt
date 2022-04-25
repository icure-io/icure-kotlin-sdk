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


import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param direct 
 * @param char 
 * @param short 
 * @param int 
 * @param long 
 * @param float 
 * @param double 
 * @param readOnly 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class InlineResponse200 (

    @field:JsonProperty("direct")
    val direct: kotlin.Boolean? = null,

    @field:JsonProperty("char")
    val char: kotlin.String? = null,

    @field:JsonProperty("short")
    val short: kotlin.Int? = null,

    @field:JsonProperty("int")
    val int: kotlin.Int? = null,

    @field:JsonProperty("long")
    val long: kotlin.Long? = null,

    @field:JsonProperty("float")
    val float: kotlin.Float? = null,

    @field:JsonProperty("double")
    val double: kotlin.Double? = null,

    @field:JsonProperty("readOnly")
    val readOnly: kotlin.Boolean? = null

)
