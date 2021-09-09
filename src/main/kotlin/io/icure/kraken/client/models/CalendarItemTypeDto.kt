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


import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param id 
 * @param duration 
 * @param docIds 
 * @param otherInfos 
 * @param subjectByLanguage 
 * @param rev 
 * @param deletionDate hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called.
 * @param name 
 * @param color 
 * @param externalRef 
 * @param mikronoId 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class CalendarItemTypeDto (

    @field:JsonProperty("id")
    val id: kotlin.String,

    @field:JsonProperty("duration")
    val duration: kotlin.Int = 0,

    @field:JsonProperty("docIds")
    val docIds: kotlin.collections.List<kotlin.String> = listOf(),

    @field:JsonProperty("otherInfos")
    val otherInfos: kotlin.collections.Map<kotlin.String, kotlin.String> = mapOf(),

    @field:JsonProperty("subjectByLanguage")
    val subjectByLanguage: kotlin.collections.Map<kotlin.String, kotlin.String> = mapOf(),

    @field:JsonProperty("rev")
    val rev: kotlin.String? = null,

    /* hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. */
    @field:JsonProperty("deletionDate")
    val deletionDate: kotlin.Long? = null,

    @field:JsonProperty("name")
    val name: kotlin.String? = null,

    @field:JsonProperty("color")
    val color: kotlin.String? = null,

    @field:JsonProperty("externalRef")
    val externalRef: kotlin.String? = null,

    @field:JsonProperty("mikronoId")
    val mikronoId: kotlin.String? = null

)

