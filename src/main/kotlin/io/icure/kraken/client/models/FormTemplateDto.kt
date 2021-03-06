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

import io.icure.kraken.client.models.CodeStubDto
import io.icure.kraken.client.models.DocumentGroupDto
import io.icure.kraken.client.models.FormLayout
import io.icure.kraken.client.models.FormTemplateLayout

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param id 
 * @param reports 
 * @param tags 
 * @param rev 
 * @param deletionDate hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called.
 * @param layout 
 * @param templateLayout 
 * @param name 
 * @param guid 
 * @param group 
 * @param descr 
 * @param disabled 
 * @param specialty 
 * @param author 
 * @param formInstancePreferredLocation 
 * @param keyboardShortcut 
 * @param shortReport 
 * @param mediumReport 
 * @param longReport 
 * @param layoutAttachmentId 
 * @param templateLayoutAttachmentId 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class FormTemplateDto (

    @field:JsonProperty("id")
    val id: kotlin.String,

    @field:JsonProperty("reports")
    val reports: kotlin.collections.List<kotlin.String> = listOf(),

    @field:JsonProperty("tags")
    val tags: kotlin.collections.List<CodeStubDto> = listOf(),

    @field:JsonProperty("rev")
    val rev: kotlin.String? = null,

    /* hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. */
    @field:JsonProperty("deletionDate")
    val deletionDate: kotlin.Long? = null,

    @field:JsonProperty("layout")
    val layout: FormLayout? = null,

    @field:JsonProperty("templateLayout")
    val templateLayout: FormTemplateLayout? = null,

    @field:JsonProperty("name")
    val name: kotlin.String? = null,

    @field:JsonProperty("guid")
    val guid: kotlin.String? = null,

    @field:JsonProperty("group")
    val group: DocumentGroupDto? = null,

    @field:JsonProperty("descr")
    val descr: kotlin.String? = null,

    @field:JsonProperty("disabled")
    val disabled: kotlin.String? = null,

    @field:JsonProperty("specialty")
    val specialty: CodeStubDto? = null,

    @field:JsonProperty("author")
    val author: kotlin.String? = null,

    @field:JsonProperty("formInstancePreferredLocation")
    val formInstancePreferredLocation: kotlin.String? = null,

    @field:JsonProperty("keyboardShortcut")
    val keyboardShortcut: kotlin.String? = null,

    @field:JsonProperty("shortReport")
    val shortReport: kotlin.String? = null,

    @field:JsonProperty("mediumReport")
    val mediumReport: kotlin.String? = null,

    @field:JsonProperty("longReport")
    val longReport: kotlin.String? = null,

    @field:JsonProperty("layoutAttachmentId")
    val layoutAttachmentId: kotlin.String? = null,

    @field:JsonProperty("templateLayoutAttachmentId")
    val templateLayoutAttachmentId: kotlin.String? = null

)

