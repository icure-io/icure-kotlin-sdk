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
import io.icure.kraken.client.models.ServiceLinkDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * This entity represents a sub-contact. It is serialized in JSON and saved in the underlying icure-contact CouchDB database.
 *
 * @param tags A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags.
 * @param codes A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes
 * @param services List of all services provided to the patient under a given contact which is linked by this sub-contact to other structuring elements.
 * @param id The Id of the sub-contact. We encourage using either a v4 UUID or a HL7 Id.
 * @param created The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param modified The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param author The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param responsible The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param medicalLocationId The id of the medical location where this entity was created.
 * @param endOfLife Soft delete (unix epoch in ms) timestamp of the object.
 * @param descr Description of the sub-contact
 * @param protocol Protocol based on which the sub-contact was used for linking services to structuring elements
 * @param status 
 * @param formId Id of the form used in the sub-contact. Several sub-contacts with the same form ID can coexist as long as they are in different contacts or they relate to a different planOfActionID
 * @param planOfActionId Id of the plan of action (healthcare approach) that is linked by the sub-contact to a service.
 * @param healthElementId Id of the healthcare element that is linked by the sub-contact to a service
 * @param classificationId 
 * @param encryptedSelf The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class SubContactDto (

    /* A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. */
    @field:JsonProperty("tags")
    val tags: kotlin.collections.List<CodeStubDto> = listOf(),

    /* A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes */
    @field:JsonProperty("codes")
    val codes: kotlin.collections.List<CodeStubDto> = listOf(),

    /* List of all services provided to the patient under a given contact which is linked by this sub-contact to other structuring elements. */
    @field:JsonProperty("services")
    val services: kotlin.collections.List<ServiceLinkDto> = listOf(),

    /* The Id of the sub-contact. We encourage using either a v4 UUID or a HL7 Id. */
    @field:JsonProperty("id")
    val id: kotlin.String? = null,

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

    /* Description of the sub-contact */
    @field:JsonProperty("descr")
    val descr: kotlin.String? = null,

    /* Protocol based on which the sub-contact was used for linking services to structuring elements */
    @field:JsonProperty("protocol")
    val protocol: kotlin.String? = null,

    @field:JsonProperty("status")
    val status: kotlin.Int? = null,

    /* Id of the form used in the sub-contact. Several sub-contacts with the same form ID can coexist as long as they are in different contacts or they relate to a different planOfActionID */
    @field:JsonProperty("formId")
    val formId: kotlin.String? = null,

    /* Id of the plan of action (healthcare approach) that is linked by the sub-contact to a service. */
    @field:JsonProperty("planOfActionId")
    val planOfActionId: kotlin.String? = null,

    /* Id of the healthcare element that is linked by the sub-contact to a service */
    @field:JsonProperty("healthElementId")
    val healthElementId: kotlin.String? = null,

    @field:JsonProperty("classificationId")
    val classificationId: kotlin.String? = null,

    /* The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. */
    @field:JsonProperty("encryptedSelf")
    val encryptedSelf: kotlin.String? = null

)

