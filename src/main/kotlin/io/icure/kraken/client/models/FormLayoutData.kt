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

import io.icure.kraken.client.models.ContentDto
import io.icure.kraken.client.models.Editor
import io.icure.kraken.client.models.FormDataOption
import io.icure.kraken.client.models.FormPlanning
import io.icure.kraken.client.models.Formula
import io.icure.kraken.client.models.GuiCode
import io.icure.kraken.client.models.GuiCodeType
import io.icure.kraken.client.models.Suggest

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param subForm 
 * @param irrelevant 
 * @param determinesSscontactName 
 * @param type 
 * @param name 
 * @param sortOrder 
 * @param options 
 * @param descr 
 * @param label 
 * @param editor 
 * @param defaultValue 
 * @param defaultStatus 
 * @param suggest 
 * @param plannings 
 * @param tags 
 * @param codes 
 * @param codeTypes 
 * @param formulas 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class FormLayoutData (

    @field:JsonProperty("subForm")
    val subForm: kotlin.Boolean? = null,

    @field:JsonProperty("irrelevant")
    val irrelevant: kotlin.Boolean? = null,

    @field:JsonProperty("determinesSscontactName")
    val determinesSscontactName: kotlin.Boolean? = null,

    @field:JsonProperty("type")
    val type: kotlin.String? = null,

    @field:JsonProperty("name")
    val name: kotlin.String? = null,

    @field:JsonProperty("sortOrder")
    val sortOrder: kotlin.Double? = null,

    @field:JsonProperty("options")
    val options: kotlin.collections.Map<kotlin.String, FormDataOption>? = null,

    @field:JsonProperty("descr")
    val descr: kotlin.String? = null,

    @field:JsonProperty("label")
    val label: kotlin.String? = null,

    @field:JsonProperty("editor")
    val editor: Editor? = null,

    @field:JsonProperty("defaultValue")
    val defaultValue: kotlin.collections.List<ContentDto>? = null,

    @field:JsonProperty("defaultStatus")
    val defaultStatus: kotlin.Int? = null,

    @field:JsonProperty("suggest")
    val suggest: kotlin.collections.List<Suggest>? = null,

    @field:JsonProperty("plannings")
    val plannings: kotlin.collections.List<FormPlanning>? = null,

    @field:JsonProperty("tags")
    val tags: kotlin.collections.List<GuiCode>? = null,

    @field:JsonProperty("codes")
    val codes: kotlin.collections.List<GuiCode>? = null,

    @field:JsonProperty("codeTypes")
    val codeTypes: kotlin.collections.List<GuiCodeType>? = null,

    @field:JsonProperty("formulas")
    val formulas: kotlin.collections.List<Formula>? = null

)

