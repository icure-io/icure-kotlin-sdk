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

import io.icure.kraken.client.models.CareTeamMembershipDto
import io.icure.kraken.client.models.CodeStubDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * List of healthcare approaches.
 *
 * @param id 
 * @param tags A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags.
 * @param codes A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes
 * @param status bit 0: active/inactive, bit 1: relevant/irrelevant, bit 2 : present/absent, ex: 0 = active,relevant and present
 * @param documentIds 
 * @param careTeamMemberships Members of the careteam involved in this approach
 * @param relevant 
 * @param created The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param modified The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param author The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param responsible The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param medicalLocationId The id of the medical location where this entity was created.
 * @param endOfLife Soft delete (unix epoch in ms) timestamp of the object.
 * @param prescriberId The id of the hcp who prescribed this healthcare approach
 * @param valueDate The date (unix epoch in ms) when the healthcare approach is noted to have started and also closes on the same date
 * @param openingDate The date (unix epoch in ms) of the start of the healthcare approach.
 * @param closingDate The date (unix epoch in ms) marking the end of the healthcare approach.
 * @param deadlineDate The date (unix epoch in ms) when the healthcare approach has to be carried out.
 * @param name The name of the healthcare approach.
 * @param descr Description of the healthcare approach.
 * @param note Note about the healthcare approach.
 * @param idOpeningContact Id of the opening contact when the healthcare approach was created.
 * @param idClosingContact Id of the closing contact for the healthcare approach.
 * @param numberOfCares The number of individual cares already performed in the course of this healthcare approach
 * @param encryptedSelf The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class PlanOfActionDto (

    @field:JsonProperty("id")
    val id: kotlin.String,

    /* A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. */
    @field:JsonProperty("tags")
    val tags: kotlin.collections.List<CodeStubDto>,

    /* A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes */
    @field:JsonProperty("codes")
    val codes: kotlin.collections.List<CodeStubDto>,

    /* bit 0: active/inactive, bit 1: relevant/irrelevant, bit 2 : present/absent, ex: 0 = active,relevant and present */
    @field:JsonProperty("status")
    val status: kotlin.Int,

    @field:JsonProperty("documentIds")
    @Deprecated(message = "This property is deprecated.")
    val documentIds: kotlin.collections.List<kotlin.String>,

    /* Members of the careteam involved in this approach */
    @field:JsonProperty("careTeamMemberships")
    val careTeamMemberships: kotlin.collections.List<CareTeamMembershipDto>,

    @field:JsonProperty("relevant")
    @Deprecated(message = "This property is deprecated.")
    val relevant: kotlin.Boolean,

    /* The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server. */
    @field:JsonProperty("created")
    val created: kotlin.Long? = null,

    /* The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server. */
    @field:JsonProperty("modified")
    val modified: kotlin.Long? = null,

    /* The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server. */
    @field:JsonProperty("author")
    val author: kotlin.String? = null,

    /* The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server. */
    @field:JsonProperty("responsible")
    val responsible: kotlin.String? = null,

    /* The id of the medical location where this entity was created. */
    @field:JsonProperty("medicalLocationId")
    val medicalLocationId: kotlin.String? = null,

    /* Soft delete (unix epoch in ms) timestamp of the object. */
    @field:JsonProperty("endOfLife")
    val endOfLife: kotlin.Long? = null,

    /* The id of the hcp who prescribed this healthcare approach */
    @field:JsonProperty("prescriberId")
    val prescriberId: kotlin.String? = null,

    /* The date (unix epoch in ms) when the healthcare approach is noted to have started and also closes on the same date */
    @field:JsonProperty("valueDate")
    val valueDate: kotlin.Long? = null,

    /* The date (unix epoch in ms) of the start of the healthcare approach. */
    @field:JsonProperty("openingDate")
    val openingDate: kotlin.Long? = null,

    /* The date (unix epoch in ms) marking the end of the healthcare approach. */
    @field:JsonProperty("closingDate")
    val closingDate: kotlin.Long? = null,

    /* The date (unix epoch in ms) when the healthcare approach has to be carried out. */
    @field:JsonProperty("deadlineDate")
    val deadlineDate: kotlin.Long? = null,

    /* The name of the healthcare approach. */
    @field:JsonProperty("name")
    val name: kotlin.String? = null,

    /* Description of the healthcare approach. */
    @field:JsonProperty("descr")
    val descr: kotlin.String? = null,

    /* Note about the healthcare approach. */
    @field:JsonProperty("note")
    val note: kotlin.String? = null,

    /* Id of the opening contact when the healthcare approach was created. */
    @field:JsonProperty("idOpeningContact")
    val idOpeningContact: kotlin.String? = null,

    /* Id of the closing contact for the healthcare approach. */
    @field:JsonProperty("idClosingContact")
    val idClosingContact: kotlin.String? = null,

    /* The number of individual cares already performed in the course of this healthcare approach */
    @field:JsonProperty("numberOfCares")
    @Deprecated(message = "This property is deprecated.")
    val numberOfCares: kotlin.Int? = null,

    /* The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. */
    @field:JsonProperty("encryptedSelf")
    val encryptedSelf: kotlin.String? = null

)

