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
 * @param durationEstimated 
 * @param dateBased 
 * @param timeBased 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class WebSessionMaxIdleTimeUnits (

    @field:JsonProperty("durationEstimated")
    val durationEstimated: kotlin.Boolean? = null,

    @field:JsonProperty("dateBased")
    val dateBased: kotlin.Boolean? = null,

    @field:JsonProperty("timeBased")
    val timeBased: kotlin.Boolean? = null

)

