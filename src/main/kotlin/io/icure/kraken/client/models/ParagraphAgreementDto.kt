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

import io.icure.kraken.client.models.AgreementAppendixDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param timestamp 
 * @param paragraph 
 * @param accepted 
 * @param inTreatment 
 * @param canceled 
 * @param careProviderReference 
 * @param decisionReference 
 * @param start 
 * @param end 
 * @param cancelationDate 
 * @param quantityValue 
 * @param quantityUnit 
 * @param ioRequestReference 
 * @param responseType 
 * @param refusalJustification 
 * @param verses 
 * @param coverageType 
 * @param unitNumber 
 * @param strength 
 * @param strengthUnit 
 * @param agreementAppendices 
 * @param documentId 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class ParagraphAgreementDto (

    @field:JsonProperty("timestamp")
    val timestamp: kotlin.Long? = null,

    @field:JsonProperty("paragraph")
    val paragraph: kotlin.String? = null,

    @field:JsonProperty("accepted")
    val accepted: kotlin.Boolean? = null,

    @field:JsonProperty("inTreatment")
    val inTreatment: kotlin.Boolean? = null,

    @field:JsonProperty("canceled")
    val canceled: kotlin.Boolean? = null,

    @field:JsonProperty("careProviderReference")
    val careProviderReference: kotlin.String? = null,

    @field:JsonProperty("decisionReference")
    val decisionReference: kotlin.String? = null,

    @field:JsonProperty("start")
    val start: kotlin.Long? = null,

    @field:JsonProperty("end")
    val end: kotlin.Long? = null,

    @field:JsonProperty("cancelationDate")
    val cancelationDate: kotlin.Long? = null,

    @field:JsonProperty("quantityValue")
    val quantityValue: kotlin.Double? = null,

    @field:JsonProperty("quantityUnit")
    val quantityUnit: kotlin.String? = null,

    @field:JsonProperty("ioRequestReference")
    val ioRequestReference: kotlin.String? = null,

    @field:JsonProperty("responseType")
    val responseType: kotlin.String? = null,

    @field:JsonProperty("refusalJustification")
    val refusalJustification: kotlin.collections.Map<kotlin.String, kotlin.String>? = null,

    @field:JsonProperty("verses")
    val verses: kotlin.collections.Set<kotlin.Long>? = null,

    @field:JsonProperty("coverageType")
    val coverageType: kotlin.String? = null,

    @field:JsonProperty("unitNumber")
    val unitNumber: kotlin.Double? = null,

    @field:JsonProperty("strength")
    val strength: kotlin.Double? = null,

    @field:JsonProperty("strengthUnit")
    val strengthUnit: kotlin.String? = null,

    @field:JsonProperty("agreementAppendices")
    val agreementAppendices: kotlin.collections.List<AgreementAppendixDto>? = null,

    @field:JsonProperty("documentId")
    val documentId: kotlin.String? = null

)

