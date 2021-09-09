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

import io.icure.kraken.client.models.CodeStubDto
import io.icure.kraken.client.models.ContentDto
import io.icure.kraken.client.models.DelegationDto
import io.icure.kraken.client.models.IdentifierDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * This entity represents a Service. A Service is created in the course a contact. Services include subjective information provided by the patient, such as complaints, reason for visit, feelings, etc. or objective information like bio-metric measures (blood pressure, temperature, heart beat, etc.), or physical exam description, diagnosis, prescription, integration of lab reports from another healthcare party, action plan, etc. Any action performed by the healthcare party which is relevant for the healthcare element of a patient is considered a service. The services can be linked to healthcare elements or other structuring elements of the medical record
 *
 * @param id The Id of the Service. We encourage using either a v4 UUID or a HL7 Id.
 * @param identifier 
 * @param cryptedForeignKeys The public patient key, encrypted here for separate Crypto Actors.
 * @param delegations The delegations giving access to connected healthcare information.
 * @param encryptionKeys The contact secret encryption key used to encrypt the secured properties (like services for example), encrypted for separate Crypto Actors.
 * @param label 
 * @param content The type of the content recorded in the documents for the service
 * @param textIndexes 
 * @param invoicingCodes List of invoicing codes
 * @param qualifiedLinks Links towards related services (possibly in other contacts)
 * @param codes A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes
 * @param tags A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags.
 * @param contactId Id of the contact during which the service is provided
 * @param subContactIds List of IDs of all sub-contacts that link the service to structural elements. Only used when the Service is emitted outside of its contact
 * @param plansOfActionIds List of IDs of all plans of actions (healthcare approaches) as a part of which the Service is provided. Only used when the Service is emitted outside of its contact
 * @param healthElementsIds List of IDs of all healthcare elements for which the service is provided. Only used when the Service is emitted outside of its contact
 * @param formIds List of Ids of all forms linked to the Service. Only used when the Service is emitted outside of its contact.
 * @param secretForeignKeys The secret patient key, encrypted in the patient document, in clear here.
 * @param dataClassName 
 * @param index 
 * @param encryptedContent 
 * @param valueDate 
 * @param openingDate 
 * @param closingDate 
 * @param formId 
 * @param created The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param modified The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param endOfLife Soft delete (unix epoch in ms) timestamp of the object.
 * @param author The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param responsible The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param medicalLocationId The id of the medical location where this entity was created.
 * @param comment Text, comments on the Service provided
 * @param status 
 * @param encryptedSelf The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class ServiceDto (

    /* The Id of the Service. We encourage using either a v4 UUID or a HL7 Id. */
    @field:JsonProperty("id")
    val id: kotlin.String,

    @field:JsonProperty("identifier")
    val identifier: kotlin.collections.List<IdentifierDto> = listOf(),

    /* The public patient key, encrypted here for separate Crypto Actors. */
    @field:JsonProperty("cryptedForeignKeys")
    val cryptedForeignKeys: kotlin.collections.Map<kotlin.String, kotlin.collections.Set<DelegationDto>> = mapOf(),

    /* The delegations giving access to connected healthcare information. */
    @field:JsonProperty("delegations")
    val delegations: kotlin.collections.Map<kotlin.String, kotlin.collections.Set<DelegationDto>> = mapOf(),

    /* The contact secret encryption key used to encrypt the secured properties (like services for example), encrypted for separate Crypto Actors. */
    @field:JsonProperty("encryptionKeys")
    val encryptionKeys: kotlin.collections.Map<kotlin.String, kotlin.collections.Set<DelegationDto>> = mapOf(),

    @field:JsonProperty("label")
    val label: kotlin.String,

    /* The type of the content recorded in the documents for the service */
    @field:JsonProperty("content")
    val content: kotlin.collections.Map<kotlin.String, ContentDto> = mapOf(),

    @field:JsonProperty("textIndexes")
    val textIndexes: kotlin.collections.Map<kotlin.String, kotlin.String> = mapOf(),

    /* List of invoicing codes */
    @field:JsonProperty("invoicingCodes")
    val invoicingCodes: kotlin.collections.List<kotlin.String> = listOf(),

    /* Links towards related services (possibly in other contacts) */
    @field:JsonProperty("qualifiedLinks")
    val qualifiedLinks: kotlin.collections.Map<kotlin.String, kotlin.collections.Map<kotlin.String, kotlin.String>> = mapOf(),

    /* A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes */
    @field:JsonProperty("codes")
    val codes: kotlin.collections.List<CodeStubDto> = listOf(),

    /* A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. */
    @field:JsonProperty("tags")
    val tags: kotlin.collections.List<CodeStubDto> = listOf(),

    /* Id of the contact during which the service is provided */
    @field:JsonProperty("contactId")
    val contactId: kotlin.String? = null,

    /* List of IDs of all sub-contacts that link the service to structural elements. Only used when the Service is emitted outside of its contact */
    @field:JsonProperty("subContactIds")
    val subContactIds: kotlin.collections.Set<kotlin.String>? = null,

    /* List of IDs of all plans of actions (healthcare approaches) as a part of which the Service is provided. Only used when the Service is emitted outside of its contact */
    @field:JsonProperty("plansOfActionIds")
    val plansOfActionIds: kotlin.collections.Set<kotlin.String>? = null,

    /* List of IDs of all healthcare elements for which the service is provided. Only used when the Service is emitted outside of its contact */
    @field:JsonProperty("healthElementsIds")
    val healthElementsIds: kotlin.collections.Set<kotlin.String>? = null,

    /* List of Ids of all forms linked to the Service. Only used when the Service is emitted outside of its contact. */
    @field:JsonProperty("formIds")
    val formIds: kotlin.collections.Set<kotlin.String>? = null,

    /* The secret patient key, encrypted in the patient document, in clear here. */
    @field:JsonProperty("secretForeignKeys")
    val secretForeignKeys: kotlin.collections.Set<kotlin.String>? = null,

    @field:JsonProperty("dataClassName")
    val dataClassName: kotlin.String? = null,

    @field:JsonProperty("index")
    val index: kotlin.Long? = null,

    @field:JsonProperty("encryptedContent")
    @Deprecated(message = "This property is deprecated.")
    val encryptedContent: kotlin.String? = null,

    @field:JsonProperty("valueDate")
    val valueDate: kotlin.Long? = null,

    @field:JsonProperty("openingDate")
    val openingDate: kotlin.Long? = null,

    @field:JsonProperty("closingDate")
    val closingDate: kotlin.Long? = null,

    @field:JsonProperty("formId")
    val formId: kotlin.String? = null,

    /* The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server. */
    @field:JsonProperty("created")
    val created: kotlin.Long? = null,

    /* The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server. */
    @field:JsonProperty("modified")
    val modified: kotlin.Long? = null,

    /* Soft delete (unix epoch in ms) timestamp of the object. */
    @field:JsonProperty("endOfLife")
    val endOfLife: kotlin.Long? = null,

    /* The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server. */
    @field:JsonProperty("author")
    val author: kotlin.String? = null,

    /* The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server. */
    @field:JsonProperty("responsible")
    val responsible: kotlin.String? = null,

    /* The id of the medical location where this entity was created. */
    @field:JsonProperty("medicalLocationId")
    val medicalLocationId: kotlin.String? = null,

    /* Text, comments on the Service provided */
    @field:JsonProperty("comment")
    val comment: kotlin.String? = null,

    @field:JsonProperty("status")
    val status: kotlin.Int? = null,

    /* The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. */
    @field:JsonProperty("encryptedSelf")
    val encryptedSelf: kotlin.String? = null

)

