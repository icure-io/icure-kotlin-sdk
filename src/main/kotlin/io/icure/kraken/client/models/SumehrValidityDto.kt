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


import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param sumehrValid 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class SumehrValidityDto (

    @field:JsonProperty("sumehrValid")
    val sumehrValid: SumehrValidityDto.SumehrValid

) {

    /**
     * 
     *
     * Values: absent,uptodate,outdated
     */
    enum class SumehrValid(val value: kotlin.String) {
        @JsonProperty(value = "absent") absent("absent"),
        @JsonProperty(value = "uptodate") uptodate("uptodate"),
        @JsonProperty(value = "outdated") outdated("outdated");
    }
}

