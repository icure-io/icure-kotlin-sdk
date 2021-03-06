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


import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param id 
 * @param rev 
 * @param deletionDate hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called.
 * @param chapterName 
 * @param paragraphName 
 * @param startDate 
 * @param createdTms 
 * @param createdUserId 
 * @param endDate 
 * @param keyStringNl 
 * @param keyStringFr 
 * @param agreementType 
 * @param processType 
 * @param legalReference 
 * @param publicationDate 
 * @param modificationDate 
 * @param processTypeOverrule 
 * @param paragraphVersion 
 * @param agreementTypePro 
 * @param modificationStatus 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class ParagraphDto (

    @field:JsonProperty("id")
    val id: kotlin.String,

    @field:JsonProperty("rev")
    val rev: kotlin.String? = null,

    /* hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. */
    @field:JsonProperty("deletionDate")
    val deletionDate: kotlin.Long? = null,

    @field:JsonProperty("chapterName")
    val chapterName: kotlin.String? = null,

    @field:JsonProperty("paragraphName")
    val paragraphName: kotlin.String? = null,

    @field:JsonProperty("startDate")
    val startDate: kotlin.Long? = null,

    @field:JsonProperty("createdTms")
    val createdTms: kotlin.Long? = null,

    @field:JsonProperty("createdUserId")
    val createdUserId: kotlin.String? = null,

    @field:JsonProperty("endDate")
    val endDate: kotlin.Long? = null,

    @field:JsonProperty("keyStringNl")
    val keyStringNl: kotlin.String? = null,

    @field:JsonProperty("keyStringFr")
    val keyStringFr: kotlin.String? = null,

    @field:JsonProperty("agreementType")
    val agreementType: kotlin.String? = null,

    @field:JsonProperty("processType")
    val processType: kotlin.Long? = null,

    @field:JsonProperty("legalReference")
    val legalReference: kotlin.String? = null,

    @field:JsonProperty("publicationDate")
    val publicationDate: kotlin.Long? = null,

    @field:JsonProperty("modificationDate")
    val modificationDate: kotlin.Long? = null,

    @field:JsonProperty("processTypeOverrule")
    val processTypeOverrule: kotlin.String? = null,

    @field:JsonProperty("paragraphVersion")
    val paragraphVersion: kotlin.Long? = null,

    @field:JsonProperty("agreementTypePro")
    val agreementTypePro: kotlin.String? = null,

    @field:JsonProperty("modificationStatus")
    val modificationStatus: kotlin.String? = null

)

