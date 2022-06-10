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

import io.icure.kraken.client.models.CodeStubDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param `value` 
 * @param min 
 * @param max 
 * @param ref 
 * @param severity 
 * @param severityCode 
 * @param evolution 
 * @param unit 
 * @param unitCodes 
 * @param comment 
 * @param comparator 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class MeasureDto (

    @field:JsonProperty("value")
    val `value`: kotlin.Double? = null,

    @field:JsonProperty("min")
    val min: kotlin.Double? = null,

    @field:JsonProperty("max")
    val max: kotlin.Double? = null,

    @field:JsonProperty("ref")
    val ref: kotlin.Double? = null,

    @field:JsonProperty("severity")
    val severity: kotlin.Int? = null,

    @field:JsonProperty("severityCode")
    val severityCode: kotlin.String? = null,

    @field:JsonProperty("evolution")
    val evolution: kotlin.Int? = null,

    @field:JsonProperty("unit")
    val unit: kotlin.String? = null,

    @field:JsonProperty("unitCodes")
    val unitCodes: kotlin.collections.Set<CodeStubDto>? = null,

    @field:JsonProperty("comment")
    val comment: kotlin.String? = null,

    @field:JsonProperty("comparator")
    val comparator: kotlin.String? = null

)

