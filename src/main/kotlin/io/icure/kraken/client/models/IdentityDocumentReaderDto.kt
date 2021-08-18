/**
 * iCure Cloud API Documentation
 *
 * Spring shop sample application
 *
 * The version of the OpenAPI document: v0.0.1
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
 * @param eidDocumentSupportType 
 * @param reasonManualEncoding 
 * @param reasonUsingVignette 
 * @param justificatifDocumentNumber 
 * @param supportSerialNumber 
 * @param timeReadingEIdDocument 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class IdentityDocumentReaderDto (

    @field:JsonProperty("eidDocumentSupportType")
    val eidDocumentSupportType: kotlin.Int = 0,

    @field:JsonProperty("reasonManualEncoding")
    val reasonManualEncoding: kotlin.Int = 0,

    @field:JsonProperty("reasonUsingVignette")
    val reasonUsingVignette: kotlin.Int = 0,

    @field:JsonProperty("justificatifDocumentNumber")
    val justificatifDocumentNumber: kotlin.String? = null,

    @field:JsonProperty("supportSerialNumber")
    val supportSerialNumber: kotlin.String? = null,

    @field:JsonProperty("timeReadingEIdDocument")
    val timeReadingEIdDocument: kotlin.Long? = null

)

