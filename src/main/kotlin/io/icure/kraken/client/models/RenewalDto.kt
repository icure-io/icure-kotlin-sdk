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

import io.icure.kraken.client.models.DurationDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param decimal 
 * @param duration 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class RenewalDto (

    @field:JsonProperty("decimal")
    val decimal: kotlin.Int? = null,

    @field:JsonProperty("duration")
    val duration: DurationDto? = null

)

