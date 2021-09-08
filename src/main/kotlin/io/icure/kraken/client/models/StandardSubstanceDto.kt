/**
 * OpenAPI definition
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v0
 * 
 *
 * Please note:
 * This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * Do not edit this file manually.
 */
package io.icure.kraken.client.models

import io.icure.kraken.client.models.SamTextDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param code 
 * @param type 
 * @param name 
 * @param definition 
 * @param url 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class StandardSubstanceDto (

    @field:JsonProperty("code")
    val code: kotlin.String? = null,

    @field:JsonProperty("type")
    val type: StandardSubstanceDto.Type? = null,

    @field:JsonProperty("name")
    val name: SamTextDto? = null,

    @field:JsonProperty("definition")
    val definition: SamTextDto? = null,

    @field:JsonProperty("url")
    val url: kotlin.String? = null

) {

    /**
     * 
     *
     * Values: cAS,dMD,eDQM,sNOMEDCT
     */
    enum class Type(val value: kotlin.String) {
        @JsonProperty(value = "CAS") cAS("CAS"),
        @JsonProperty(value = "DM_D") dMD("DM_D"),
        @JsonProperty(value = "EDQM") eDQM("EDQM"),
        @JsonProperty(value = "SNOMED_CT") sNOMEDCT("SNOMED_CT");
    }
}

