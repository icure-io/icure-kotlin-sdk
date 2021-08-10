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

import io.icure.kraken.client.models.CodeStubDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param startDate 
 * @param endDate 
 * @param school 
 * @param typeOfEducation 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class SchoolingInfoDto (

    @field:JsonProperty("startDate")
    val startDate: kotlin.Long? = null,

    @field:JsonProperty("endDate")
    val endDate: kotlin.Long? = null,

    @field:JsonProperty("school")
    val school: kotlin.String? = null,

    @field:JsonProperty("typeOfEducation")
    val typeOfEducation: CodeStubDto? = null

)

