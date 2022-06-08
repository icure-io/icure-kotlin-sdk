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

import io.icure.kraken.client.models.DeviceTypeDto
import io.icure.kraken.client.models.PackagingTypeDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param from 
 * @param to 
 * @param contentType 
 * @param contentMultiplier 
 * @param packSpecification 
 * @param deviceType 
 * @param packagingType 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class AmppComponentDto (

    @field:JsonProperty("from")
    val from: kotlin.Long? = null,

    @field:JsonProperty("to")
    val to: kotlin.Long? = null,

    @field:JsonProperty("contentType")
    val contentType: AmppComponentDto.ContentType? = null,

    @field:JsonProperty("contentMultiplier")
    val contentMultiplier: kotlin.Int? = null,

    @field:JsonProperty("packSpecification")
    val packSpecification: kotlin.String? = null,

    @field:JsonProperty("deviceType")
    val deviceType: DeviceTypeDto? = null,

    @field:JsonProperty("packagingType")
    val packagingType: PackagingTypeDto? = null

) {

    /**
     * 
     *
     * Values: aCTIVECOMPONENT,sOLVENT,dEVICE,eXCIPIENT
     */
    enum class ContentType(val value: kotlin.String) {
        @JsonProperty(value = "ACTIVE_COMPONENT") aCTIVECOMPONENT("ACTIVE_COMPONENT"),
        @JsonProperty(value = "SOLVENT") sOLVENT("SOLVENT"),
        @JsonProperty(value = "DEVICE") dEVICE("DEVICE"),
        @JsonProperty(value = "EXCIPIENT") eXCIPIENT("EXCIPIENT");
    }
}

