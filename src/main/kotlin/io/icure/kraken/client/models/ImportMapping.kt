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

import io.icure.kraken.client.models.CodeStub

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param label 
 * @param tags 
 * @param lifecycle 
 * @param content 
 * @param cdLocal 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class ImportMapping (

    @field:JsonProperty("label")
    val label: kotlin.collections.Map<kotlin.String, kotlin.String> = emptyMap(),

    @field:JsonProperty("tags")
    val tags: kotlin.collections.List<CodeStub> = emptyList(),

    @field:JsonProperty("lifecycle")
    val lifecycle: kotlin.String? = null,

    @field:JsonProperty("content")
    val content: kotlin.String? = null,

    @field:JsonProperty("cdLocal")
    val cdLocal: kotlin.String? = null

)

