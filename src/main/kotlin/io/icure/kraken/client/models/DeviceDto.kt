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
import io.icure.kraken.client.models.IdentifierDto
import io.icure.kraken.client.models.PropertyStubDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * This entity is a root level object. It represents a device. It is serialized in JSON and saved in the underlying icure-device CouchDB database.
 *
 * @param id 
 * @param identifiers 
 * @param tags A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags.
 * @param codes A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes
 * @param properties 
 * @param hcPartyKeys For each couple of HcParties (delegator and delegate), this map contains the exchange AES key. The delegator is always this hcp, the key of the map is the id of the delegate. The AES exchange key is encrypted using RSA twice : once using this hcp public key (index 0 in the Array) and once using the other hcp public key (index 1 in the Array). For a pair of HcParties. Each HcParty always has one AES exchange key for himself.
 * @param aesExchangeKeys Extra AES exchange keys, usually the ones we lost access to at some point. The structure is { publicKey: { delegateId: [aesExKey_for_this, aesExKey_for_delegate] } }
 * @param transferKeys Our private keys encrypted with our public keys. The structure is { publicKey1: { publicKey2: privateKey2_encrypted_with_publicKey1, publicKey3: privateKey3_encrypted_with_publicKey1 } }
 * @param privateKeyShamirPartitions The privateKeyShamirPartitions are used to share this hcp's private RSA key with a series of other hcParties using Shamir's algorithm. The key of the map is the hcp Id with whom this partition has been shared. The value is \"threshold⎮partition in hex\" encrypted using the the partition's holder's public RSA key
 * @param rev 
 * @param deletionDate hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called.
 * @param created The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param modified The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param author The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param responsible The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server.
 * @param endOfLife Soft delete (unix epoch in ms) timestamp of the object.
 * @param medicalLocationId The id of the medical location where this entity was created.
 * @param externalId 
 * @param name 
 * @param type 
 * @param brand 
 * @param model 
 * @param serialNumber 
 * @param parentId 
 * @param picture 
 * @param publicKey The public key of this hcp
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class DeviceDto (

    @field:JsonProperty("id")
    val id: kotlin.String,

    @field:JsonProperty("identifiers")
    val identifiers: kotlin.collections.List<IdentifierDto> = emptyList(),

    /* A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. */
    @field:JsonProperty("tags")
    val tags: kotlin.collections.List<CodeStubDto> = emptyList(),

    /* A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes */
    @field:JsonProperty("codes")
    val codes: kotlin.collections.List<CodeStubDto> = emptyList(),

    @field:JsonProperty("properties")
    val properties: kotlin.collections.List<PropertyStubDto> = emptyList(),

    /* For each couple of HcParties (delegator and delegate), this map contains the exchange AES key. The delegator is always this hcp, the key of the map is the id of the delegate. The AES exchange key is encrypted using RSA twice : once using this hcp public key (index 0 in the Array) and once using the other hcp public key (index 1 in the Array). For a pair of HcParties. Each HcParty always has one AES exchange key for himself. */
    @field:JsonProperty("hcPartyKeys")
    val hcPartyKeys: kotlin.collections.Map<kotlin.String, kotlin.collections.List<kotlin.String>> = emptyMap(),

    /* Extra AES exchange keys, usually the ones we lost access to at some point. The structure is { publicKey: { delegateId: [aesExKey_for_this, aesExKey_for_delegate] } } */
    @field:JsonProperty("aesExchangeKeys")
    val aesExchangeKeys: kotlin.collections.Map<kotlin.String, kotlin.collections.Map<kotlin.String, kotlin.collections.List<kotlin.String>>> = emptyMap(),

    /* Our private keys encrypted with our public keys. The structure is { publicKey1: { publicKey2: privateKey2_encrypted_with_publicKey1, publicKey3: privateKey3_encrypted_with_publicKey1 } } */
    @field:JsonProperty("transferKeys")
    val transferKeys: kotlin.collections.Map<kotlin.String, kotlin.collections.Map<kotlin.String, kotlin.String>> = emptyMap(),

    /* The privateKeyShamirPartitions are used to share this hcp's private RSA key with a series of other hcParties using Shamir's algorithm. The key of the map is the hcp Id with whom this partition has been shared. The value is \"threshold⎮partition in hex\" encrypted using the the partition's holder's public RSA key */
    @field:JsonProperty("privateKeyShamirPartitions")
    val privateKeyShamirPartitions: kotlin.collections.Map<kotlin.String, kotlin.String> = emptyMap(),

    @field:JsonProperty("rev")
    val rev: kotlin.String? = null,

    /* hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. */
    @field:JsonProperty("deletionDate")
    val deletionDate: kotlin.Long? = null,

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

    /* Soft delete (unix epoch in ms) timestamp of the object. */
    @field:JsonProperty("endOfLife")
    val endOfLife: kotlin.Long? = null,

    /* The id of the medical location where this entity was created. */
    @field:JsonProperty("medicalLocationId")
    val medicalLocationId: kotlin.String? = null,

    @field:JsonProperty("externalId")
    val externalId: kotlin.String? = null,

    @field:JsonProperty("name")
    val name: kotlin.String? = null,

    @field:JsonProperty("type")
    val type: kotlin.String? = null,

    @field:JsonProperty("brand")
    val brand: kotlin.String? = null,

    @field:JsonProperty("model")
    val model: kotlin.String? = null,

    @field:JsonProperty("serialNumber")
    val serialNumber: kotlin.String? = null,

    @field:JsonProperty("parentId")
    val parentId: kotlin.String? = null,

    @field:JsonProperty("picture")
    val picture: kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper>? = null,

    /* The public key of this hcp */
    @field:JsonProperty("publicKey")
    val publicKey: kotlin.String? = null

)

