/**
 * iCure Data Stack API Documentation
 *
 * The iCure Data Stack Application API is the native interface to iCure. This version is obsolete, please use v2.
 *
 * The version of the OpenAPI document: v1
 * 
 *
 * Please note:
 * This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * Do not edit this file manually.
 */
package io.icure.kraken.client.models

import io.icure.kraken.client.models.FormLayoutData

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param formDataList 
 * @param columns 
 * @param shouldDisplay 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class FormColumn (

    @field:JsonProperty("formDataList")
    val formDataList: kotlin.collections.List<FormLayoutData>? = null,

    @field:JsonProperty("columns")
    val columns: kotlin.String? = null,

    @field:JsonProperty("shouldDisplay")
    val shouldDisplay: kotlin.Boolean? = null

)

