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

import io.icure.kraken.client.models.ValorisationDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param valorisations 
 * @param code 
 * @param flatRateType 
 * @param label 
 * @param encryptedSelf The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class FlatRateTarificationDto (

    @field:JsonProperty("valorisations")
    val valorisations: kotlin.collections.List<ValorisationDto> = listOf(),

    @field:JsonProperty("code")
    val code: kotlin.String? = null,

    @field:JsonProperty("flatRateType")
    val flatRateType: FlatRateTarificationDto.FlatRateType? = null,

    @field:JsonProperty("label")
    val label: kotlin.collections.Map<kotlin.String, kotlin.String>? = null,

    /* The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. */
    @field:JsonProperty("encryptedSelf")
    val encryptedSelf: kotlin.String? = null

) {

    /**
     * 
     *
     * Values: physician,physiotherapist,nurse,ptd
     */
    enum class FlatRateType(val value: kotlin.String) {
        @JsonProperty(value = "physician") physician("physician"),
        @JsonProperty(value = "physiotherapist") physiotherapist("physiotherapist"),
        @JsonProperty(value = "nurse") nurse("nurse"),
        @JsonProperty(value = "ptd") ptd("ptd");
    }
}

