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

import io.icure.kraken.client.models.RouteOfAdministrationDto
import io.icure.kraken.client.models.SamTextDto
import io.icure.kraken.client.models.VirtualFormDto
import io.icure.kraken.client.models.VirtualIngredientDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param code 
 * @param virtualForm 
 * @param routeOfAdministrations 
 * @param name 
 * @param phaseNumber 
 * @param virtualIngredients 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class VmpComponentDto (

    @field:JsonProperty("code")
    val code: kotlin.String? = null,

    @field:JsonProperty("virtualForm")
    val virtualForm: VirtualFormDto? = null,

    @field:JsonProperty("routeOfAdministrations")
    val routeOfAdministrations: kotlin.collections.List<RouteOfAdministrationDto>? = null,

    @field:JsonProperty("name")
    val name: SamTextDto? = null,

    @field:JsonProperty("phaseNumber")
    val phaseNumber: kotlin.Int? = null,

    @field:JsonProperty("virtualIngredients")
    val virtualIngredients: kotlin.collections.List<VirtualIngredientDto>? = null

)

