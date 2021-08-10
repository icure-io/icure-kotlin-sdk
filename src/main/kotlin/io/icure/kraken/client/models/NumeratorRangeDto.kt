/**
* iCure Cloud API Documentation
* Spring shop sample application
*
* The version of the OpenAPI document: v0.0.1
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
package io.icure.kraken.client.models


import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param min 
 * @param max 
 * @param unit 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class NumeratorRangeDto (

    @field:JsonProperty("min")
    val min: java.math.BigDecimal? = null,

    @field:JsonProperty("max")
    val max: java.math.BigDecimal? = null,

    @field:JsonProperty("unit")
    val unit: kotlin.String? = null

)

