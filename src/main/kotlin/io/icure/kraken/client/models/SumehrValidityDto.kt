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


/**
 * 
 *
 * @param sumehrValid 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
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

