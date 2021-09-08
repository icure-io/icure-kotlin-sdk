/**
 * OpenAPI definition
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v0
 * 
 *
 * Please note:
 * This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * Do not edit this file manually.
 */
package io.icure.kraken.client.models

import io.icure.kraken.client.models.FormSection
import io.icure.kraken.client.models.Tag

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param name 
 * @param width 
 * @param height 
 * @param descr 
 * @param tag 
 * @param guid 
 * @param group 
 * @param sections 
 * @param importedServiceXPaths 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class FormLayout (

    @field:JsonProperty("name")
    val name: kotlin.String? = null,

    @field:JsonProperty("width")
    val width: kotlin.Double? = null,

    @field:JsonProperty("height")
    val height: kotlin.Double? = null,

    @field:JsonProperty("descr")
    val descr: kotlin.String? = null,

    @field:JsonProperty("tag")
    val tag: Tag? = null,

    @field:JsonProperty("guid")
    val guid: kotlin.String? = null,

    @field:JsonProperty("group")
    val group: kotlin.String? = null,

    @field:JsonProperty("sections")
    val sections: kotlin.collections.List<FormSection>? = null,

    @field:JsonProperty("importedServiceXPaths")
    val importedServiceXPaths: kotlin.collections.List<kotlin.String>? = null

)

