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

import io.icure.kraken.client.models.SamTextDto
import io.icure.kraken.client.models.StandardSubstanceDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param id 
 * @param code 
 * @param chemicalForm 
 * @param name 
 * @param note 
 * @param standardSubstances 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class SubstanceStubDto (

    @field:JsonProperty("id")
    val id: kotlin.String? = null,

    @field:JsonProperty("code")
    val code: kotlin.String? = null,

    @field:JsonProperty("chemicalForm")
    val chemicalForm: kotlin.String? = null,

    @field:JsonProperty("name")
    val name: SamTextDto? = null,

    @field:JsonProperty("note")
    val note: SamTextDto? = null,

    @field:JsonProperty("standardSubstances")
    val standardSubstances: kotlin.collections.List<StandardSubstanceDto>? = null

)

