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
 * @param id 
 * @param updateSeq 
 * @param fileSize 
 * @param externalSize 
 * @param activeSize 
 * @param docs 
 * @param q 
 * @param n 
 * @param w 
 * @param r 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class DatabaseInfoDto (

    @field:JsonProperty("id")
    val id: kotlin.String,

    @field:JsonProperty("updateSeq")
    val updateSeq: kotlin.String? = null,

    @field:JsonProperty("fileSize")
    val fileSize: kotlin.Long? = null,

    @field:JsonProperty("externalSize")
    val externalSize: kotlin.Long? = null,

    @field:JsonProperty("activeSize")
    val activeSize: kotlin.Long? = null,

    @field:JsonProperty("docs")
    val docs: kotlin.Long? = null,

    @field:JsonProperty("q")
    val q: kotlin.Int? = null,

    @field:JsonProperty("n")
    val n: kotlin.Int? = null,

    @field:JsonProperty("w")
    val w: kotlin.Int? = null,

    @field:JsonProperty("r")
    val r: kotlin.Int? = null

)
