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
 * Revoked permissions.
 *
 * @param type 
 * @param predicate 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class PermissionItemDto (

    @field:JsonProperty("type")
    val type: PermissionItemDto.Type,

    @field:JsonProperty("predicate")
    val predicate: kotlin.Any

) {

    /**
     * 
     *
     * Values: aUTHENTICATE,aDMIN,pATIENTVIEW,pATIENTCREATE,pATIENTCHANGEDELETE,mEDICALDATAVIEW,mEDICALDATACREATE,mEDICALCHANGEDELETE,fINANCIALDATAVIEW,fINANCIALDATACREATE,fINANCIALCHANGEDELETE
     */
    enum class Type(val value: kotlin.String) {
        @JsonProperty(value = "AUTHENTICATE") aUTHENTICATE("AUTHENTICATE"),
        @JsonProperty(value = "ADMIN") aDMIN("ADMIN"),
        @JsonProperty(value = "PATIENT_VIEW") pATIENTVIEW("PATIENT_VIEW"),
        @JsonProperty(value = "PATIENT_CREATE") pATIENTCREATE("PATIENT_CREATE"),
        @JsonProperty(value = "PATIENT_CHANGE_DELETE") pATIENTCHANGEDELETE("PATIENT_CHANGE_DELETE"),
        @JsonProperty(value = "MEDICAL_DATA_VIEW") mEDICALDATAVIEW("MEDICAL_DATA_VIEW"),
        @JsonProperty(value = "MEDICAL_DATA_CREATE") mEDICALDATACREATE("MEDICAL_DATA_CREATE"),
        @JsonProperty(value = "MEDICAL_CHANGE_DELETE") mEDICALCHANGEDELETE("MEDICAL_CHANGE_DELETE"),
        @JsonProperty(value = "FINANCIAL_DATA_VIEW") fINANCIALDATAVIEW("FINANCIAL_DATA_VIEW"),
        @JsonProperty(value = "FINANCIAL_DATA_CREATE") fINANCIALDATACREATE("FINANCIAL_DATA_CREATE"),
        @JsonProperty(value = "FINANCIAL_CHANGE_DELETE") fINANCIALCHANGEDELETE("FINANCIAL_CHANGE_DELETE");
    }
}

