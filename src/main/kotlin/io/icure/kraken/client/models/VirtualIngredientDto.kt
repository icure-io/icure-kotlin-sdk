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

import io.icure.kraken.client.models.StrengthRangeDto
import io.icure.kraken.client.models.SubstanceStubDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param from 
 * @param to 
 * @param rank 
 * @param type 
 * @param strengthRange 
 * @param substance 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class VirtualIngredientDto (

    @field:JsonProperty("from")
    val from: kotlin.Long? = null,

    @field:JsonProperty("to")
    val to: kotlin.Long? = null,

    @field:JsonProperty("rank")
    val rank: kotlin.Int? = null,

    @field:JsonProperty("type")
    val type: VirtualIngredientDto.Type? = null,

    @field:JsonProperty("strengthRange")
    val strengthRange: StrengthRangeDto? = null,

    @field:JsonProperty("substance")
    val substance: SubstanceStubDto? = null

) {

    /**
     * 
     *
     * Values: aCTIVESUBSTANCE,eXCIPIENT
     */
    enum class Type(val value: kotlin.String) {
        @JsonProperty(value = "ACTIVE_SUBSTANCE") aCTIVESUBSTANCE("ACTIVE_SUBSTANCE"),
        @JsonProperty(value = "EXCIPIENT") eXCIPIENT("EXCIPIENT");
    }
}

