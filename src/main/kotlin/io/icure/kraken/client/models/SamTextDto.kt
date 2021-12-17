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
 * @param fr 
 * @param nl 
 * @param de 
 * @param en 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class SamTextDto (

    @field:JsonProperty("fr")
    val fr: kotlin.String? = null,

    @field:JsonProperty("nl")
    val nl: kotlin.String? = null,

    @field:JsonProperty("de")
    val de: kotlin.String? = null,

    @field:JsonProperty("en")
    val en: kotlin.String? = null

)

