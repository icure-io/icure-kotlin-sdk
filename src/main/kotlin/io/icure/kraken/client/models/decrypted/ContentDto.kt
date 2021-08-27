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
package io.icure.kraken.client.models.decrypted

import io.icure.kraken.client.models.MeasureDto
import io.icure.kraken.client.models.MedicationDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * The type of the content recorded in the documents for the service
 *
 * @param stringValue
 * @param numberValue
 * @param booleanValue
 * @param instantValue
 * @param fuzzyDateValue Known values in a date. The format could have a all three (day, month and year) or values on any of these three, whatever is known.
 * @param binaryValue
 * @param documentId Id of the document in which the content is being filled.
 * @param measureValue
 * @param medicationValue
 * @param compoundValue The service for which the content is being filled
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class ContentDto (

    @field:JsonProperty("stringValue")
    val stringValue: kotlin.String? = null,

    @field:JsonProperty("numberValue")
    val numberValue: kotlin.Double? = null,

    @field:JsonProperty("booleanValue")
    val booleanValue: kotlin.Boolean? = null,

    @field:JsonProperty("instantValue")
    val instantValue: java.time.OffsetDateTime? = null,

    /* Known values in a date. The format could have a all three (day, month and year) or values on any of these three, whatever is known. */
    @field:JsonProperty("fuzzyDateValue")
    val fuzzyDateValue: kotlin.Long? = null,

    @field:JsonProperty("binaryValue")
    val binaryValue: kotlin.collections.List<kotlin.ByteArray>? = null,

    /* Id of the document in which the content is being filled. */
    @field:JsonProperty("documentId")
    val documentId: kotlin.String? = null,

    @field:JsonProperty("measureValue")
    val measureValue: MeasureDto? = null,

    @field:JsonProperty("medicationValue")
    val medicationValue: MedicationDto? = null,

    /* The service for which the content is being filled */
    @field:JsonProperty("compoundValue")
    val compoundValue: kotlin.collections.List<ServiceDto>? = null

)

