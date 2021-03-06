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

import io.icure.kraken.client.models.AddressDto
import io.icure.kraken.client.models.CodeStubDto
import io.icure.kraken.client.models.FinancialInstitutionInformationDto
import io.icure.kraken.client.models.FlatRateTarificationDto
import io.icure.kraken.client.models.HealthcarePartyHistoryStatusDto
import io.icure.kraken.client.models.IdentifierDto
import io.icure.kraken.client.models.PersonNameDto
import io.icure.kraken.client.models.PropertyStubDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * This entity is a root level object. It represents a healthcare party. It is serialized in JSON and saved in the underlying icure-healthdata CouchDB database.
 *
 * @param id the Id of the healthcare party. We encourage using either a v4 UUID or a HL7 Id.
 * @param identifier The healthcareparty's identifiers, used by the client to identify uniquely and unambiguously the HCP. However, iCure may not guarantee this uniqueness by itself : This should be done at the client side.
 * @param tags A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags.
 * @param codes A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes
 * @param names the list of all names of the healthcare party, also containing the official full name information. Ordered by preference of use. First element is therefore the official name used for the healthcare party in the application
 * @param addresses The list of addresses (with address type).
 * @param languages The list of languages spoken by the patient ordered by fluency (alpha-2 code http://www.loc.gov/standards/iso639-2/ascii_8bits.html).
 * @param statuses The healthcare party's status: 'trainee' or 'withconvention' or 'accredited'
 * @param statusHistory The healthcare party's status history
 * @param specialityCodes Medical specialty of the healthcare party codified using FHIR or Kmehr codificaiton scheme
 * @param sendFormats The type of format for contacting the healthcare party, ex: mobile, phone, email, etc.
 * @param financialInstitutionInformation List of financial information (Bank, bank account).
 * @param flatRateTarifications 
 * @param importedData 
 * @param options 
 * @param properties 
 * @param hcPartyKeys For each couple of HcParties (delegator and delegate), this map contains the exchange AES key. The delegator is always this hcp, the key of the map is the id of the delegate. The AES exchange key is encrypted using RSA twice : once using this hcp public key (index 0 in the Array) and once using the other hcp public key (index 1 in the Array). For a pair of HcParties. Each HcParty always has one AES exchange key for himself.
 * @param aesExchangeKeys Extra AES exchange keys, usually the ones we lost access to at some point. The structure is { publicKey: { delegateId: { myPubKey1: aesExKey_for_this, delegatePubKey1: aesExKey_for_delegate } } }
 * @param transferKeys Our private keys encrypted with our public keys. The structure is { publicKey1: { publicKey2: privateKey2_encrypted_with_publicKey1, publicKey3: privateKey3_encrypted_with_publicKey1 } }
 * @param privateKeyShamirPartitions The privateKeyShamirPartitions are used to share this hcp's private RSA key with a series of other hcParties using Shamir's algorithm. The key of the map is the hcp Id with whom this partition has been shared. The value is \"threshold???partition in hex\" encrypted using the the partition's holder's public RSA key
 * @param rev the revision of the healthcare party in the database, used for conflict management / optimistic locking.
 * @param created creation timestamp of the object.
 * @param modified last modification timestamp of the object.
 * @param deletionDate hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called.
 * @param name The full name of the healthcare party, used mainly when the healthcare party is an organization
 * @param lastName the lastname (surname) of the healthcare party. This is the official lastname that should be used for official administrative purposes.
 * @param firstName the firstname (name) of the healthcare party.
 * @param gender the gender of the healthcare party: male, female, indeterminate, changed, changedToMale, changedToFemale, unknown
 * @param civility Mr., Ms., Pr., Dr. ...
 * @param companyName The name of the company this healthcare party is member of
 * @param speciality Medical specialty of the healthcare party
 * @param bankAccount Bank Account identifier of the healhtcare party, IBAN, deprecated, use financial institutions instead
 * @param bic Bank Identifier Code, the SWIFT Address assigned to the bank, use financial institutions instead
 * @param proxyBankAccount 
 * @param proxyBic 
 * @param invoiceHeader All details included in the invoice header
 * @param cbe Identifier number for institution type if the healthcare party is an enterprise
 * @param ehp Identifier number for the institution if the healthcare party is an organization
 * @param userId The id of the user that usually handles this healthcare party.
 * @param parentId Id of parent of the user representing the healthcare party.
 * @param convention 
 * @param nihii National Institute for Health and Invalidity Insurance number assigned to healthcare parties (institution or person).
 * @param nihiiSpecCode 
 * @param ssin Social security inscription number.
 * @param picture A picture usually saved in JPEG format.
 * @param notes Text notes.
 * @param descr A description of the HCP, meant for the public and in multiple languages.
 * @param billingType The invoicing scheme this healthcare party adheres to : 'service fee' or 'flat rate'
 * @param type 
 * @param contactPerson 
 * @param contactPersonHcpId 
 * @param supervisorId 
 * @param publicKey The public key of this hcp
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class HealthcarePartyDto (

    /* the Id of the healthcare party. We encourage using either a v4 UUID or a HL7 Id. */
    @field:JsonProperty("id")
    val id: kotlin.String,

    /* The healthcareparty's identifiers, used by the client to identify uniquely and unambiguously the HCP. However, iCure may not guarantee this uniqueness by itself : This should be done at the client side. */
    @field:JsonProperty("identifier")
    val identifier: kotlin.collections.List<IdentifierDto> = emptyList(),

    /* A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. */
    @field:JsonProperty("tags")
    val tags: kotlin.collections.List<CodeStubDto> = emptyList(),

    /* A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes */
    @field:JsonProperty("codes")
    val codes: kotlin.collections.List<CodeStubDto> = emptyList(),

    /* the list of all names of the healthcare party, also containing the official full name information. Ordered by preference of use. First element is therefore the official name used for the healthcare party in the application */
    @field:JsonProperty("names")
    val names: kotlin.collections.List<PersonNameDto> = emptyList(),

    /* The list of addresses (with address type). */
    @field:JsonProperty("addresses")
    val addresses: kotlin.collections.List<AddressDto> = emptyList(),

    /* The list of languages spoken by the patient ordered by fluency (alpha-2 code http://www.loc.gov/standards/iso639-2/ascii_8bits.html). */
    @field:JsonProperty("languages")
    val languages: kotlin.collections.List<kotlin.String> = emptyList(),

    /* The healthcare party's status: 'trainee' or 'withconvention' or 'accredited' */
    @field:JsonProperty("statuses")
    val statuses: kotlin.collections.List<HealthcarePartyDto.Statuses> = emptyList(),

    /* The healthcare party's status history */
    @field:JsonProperty("statusHistory")
    val statusHistory: kotlin.collections.List<HealthcarePartyHistoryStatusDto> = emptyList(),

    /* Medical specialty of the healthcare party codified using FHIR or Kmehr codificaiton scheme */
    @field:JsonProperty("specialityCodes")
    val specialityCodes: kotlin.collections.List<CodeStubDto> = emptyList(),

    /* The type of format for contacting the healthcare party, ex: mobile, phone, email, etc. */
    @field:JsonProperty("sendFormats")
    val sendFormats: kotlin.collections.Map<kotlin.String, kotlin.String> = emptyMap(),

    /* List of financial information (Bank, bank account). */
    @field:JsonProperty("financialInstitutionInformation")
    val financialInstitutionInformation: kotlin.collections.List<FinancialInstitutionInformationDto> = emptyList(),

    @field:JsonProperty("flatRateTarifications")
    val flatRateTarifications: kotlin.collections.List<FlatRateTarificationDto> = emptyList(),

    @field:JsonProperty("importedData")
    val importedData: kotlin.collections.Map<kotlin.String, kotlin.String> = emptyMap(),

    @field:JsonProperty("options")
    val options: kotlin.collections.Map<kotlin.String, kotlin.String> = emptyMap(),

    @field:JsonProperty("properties")
    val properties: kotlin.collections.List<PropertyStubDto> = emptyList(),

    /* For each couple of HcParties (delegator and delegate), this map contains the exchange AES key. The delegator is always this hcp, the key of the map is the id of the delegate. The AES exchange key is encrypted using RSA twice : once using this hcp public key (index 0 in the Array) and once using the other hcp public key (index 1 in the Array). For a pair of HcParties. Each HcParty always has one AES exchange key for himself. */
    @field:JsonProperty("hcPartyKeys")
    val hcPartyKeys: kotlin.collections.Map<kotlin.String, kotlin.collections.List<kotlin.String>> = emptyMap(),

    /* Extra AES exchange keys, usually the ones we lost access to at some point. The structure is { publicKey: { delegateId: { myPubKey1: aesExKey_for_this, delegatePubKey1: aesExKey_for_delegate } } } */
    @field:JsonProperty("aesExchangeKeys")
    val aesExchangeKeys: kotlin.collections.Map<kotlin.String, kotlin.collections.Map<kotlin.String, kotlin.collections.Map<kotlin.String, kotlin.String>>> = emptyMap(),

    /* Our private keys encrypted with our public keys. The structure is { publicKey1: { publicKey2: privateKey2_encrypted_with_publicKey1, publicKey3: privateKey3_encrypted_with_publicKey1 } } */
    @field:JsonProperty("transferKeys")
    val transferKeys: kotlin.collections.Map<kotlin.String, kotlin.collections.Map<kotlin.String, kotlin.String>> = emptyMap(),

    /* The privateKeyShamirPartitions are used to share this hcp's private RSA key with a series of other hcParties using Shamir's algorithm. The key of the map is the hcp Id with whom this partition has been shared. The value is \"threshold???partition in hex\" encrypted using the the partition's holder's public RSA key */
    @field:JsonProperty("privateKeyShamirPartitions")
    val privateKeyShamirPartitions: kotlin.collections.Map<kotlin.String, kotlin.String> = emptyMap(),

    /* the revision of the healthcare party in the database, used for conflict management / optimistic locking. */
    @field:JsonProperty("rev")
    val rev: kotlin.String? = null,

    /* creation timestamp of the object. */
    @field:JsonProperty("created")
    val created: kotlin.Long? = null,

    /* last modification timestamp of the object. */
    @field:JsonProperty("modified")
    val modified: kotlin.Long? = null,

    /* hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. */
    @field:JsonProperty("deletionDate")
    val deletionDate: kotlin.Long? = null,

    /* The full name of the healthcare party, used mainly when the healthcare party is an organization */
    @field:JsonProperty("name")
    val name: kotlin.String? = null,

    /* the lastname (surname) of the healthcare party. This is the official lastname that should be used for official administrative purposes. */
    @field:JsonProperty("lastName")
    val lastName: kotlin.String? = null,

    /* the firstname (name) of the healthcare party. */
    @field:JsonProperty("firstName")
    val firstName: kotlin.String? = null,

    /* the gender of the healthcare party: male, female, indeterminate, changed, changedToMale, changedToFemale, unknown */
    @field:JsonProperty("gender")
    val gender: HealthcarePartyDto.Gender? = null,

    /* Mr., Ms., Pr., Dr. ... */
    @field:JsonProperty("civility")
    val civility: kotlin.String? = null,

    /* The name of the company this healthcare party is member of */
    @field:JsonProperty("companyName")
    val companyName: kotlin.String? = null,

    /* Medical specialty of the healthcare party */
    @field:JsonProperty("speciality")
    val speciality: kotlin.String? = null,

    /* Bank Account identifier of the healhtcare party, IBAN, deprecated, use financial institutions instead */
    @field:JsonProperty("bankAccount")
    val bankAccount: kotlin.String? = null,

    /* Bank Identifier Code, the SWIFT Address assigned to the bank, use financial institutions instead */
    @field:JsonProperty("bic")
    val bic: kotlin.String? = null,

    @field:JsonProperty("proxyBankAccount")
    val proxyBankAccount: kotlin.String? = null,

    @field:JsonProperty("proxyBic")
    val proxyBic: kotlin.String? = null,

    /* All details included in the invoice header */
    @field:JsonProperty("invoiceHeader")
    val invoiceHeader: kotlin.String? = null,

    /* Identifier number for institution type if the healthcare party is an enterprise */
    @field:JsonProperty("cbe")
    val cbe: kotlin.String? = null,

    /* Identifier number for the institution if the healthcare party is an organization */
    @field:JsonProperty("ehp")
    val ehp: kotlin.String? = null,

    /* The id of the user that usually handles this healthcare party. */
    @field:JsonProperty("userId")
    val userId: kotlin.String? = null,

    /* Id of parent of the user representing the healthcare party. */
    @field:JsonProperty("parentId")
    val parentId: kotlin.String? = null,

    @field:JsonProperty("convention")
    val convention: kotlin.Int? = null,

    /* National Institute for Health and Invalidity Insurance number assigned to healthcare parties (institution or person). */
    @field:JsonProperty("nihii")
    val nihii: kotlin.String? = null,

    @field:JsonProperty("nihiiSpecCode")
    val nihiiSpecCode: kotlin.String? = null,

    /* Social security inscription number. */
    @field:JsonProperty("ssin")
    val ssin: kotlin.String? = null,

    /* A picture usually saved in JPEG format. */
    @field:JsonProperty("picture")
    val picture: io.icure.kraken.client.infrastructure.ByteArrayWrapper? = null,

    /* Text notes. */
    @field:JsonProperty("notes")
    val notes: kotlin.String? = null,

    /* A description of the HCP, meant for the public and in multiple languages. */
    @field:JsonProperty("descr")
    val descr: kotlin.collections.Map<kotlin.String, kotlin.String>? = null,

    /* The invoicing scheme this healthcare party adheres to : 'service fee' or 'flat rate' */
    @field:JsonProperty("billingType")
    val billingType: kotlin.String? = null,

    @field:JsonProperty("type")
    val type: kotlin.String? = null,

    @field:JsonProperty("contactPerson")
    val contactPerson: kotlin.String? = null,

    @field:JsonProperty("contactPersonHcpId")
    val contactPersonHcpId: kotlin.String? = null,

    @field:JsonProperty("supervisorId")
    val supervisorId: kotlin.String? = null,

    /* The public key of this hcp */
    @field:JsonProperty("publicKey")
    val publicKey: kotlin.String? = null

) {

    /**
     * The healthcare party's status: 'trainee' or 'withconvention' or 'accredited'
     *
     * Values: trainee,withconvention,accreditated
     */
    enum class Statuses(val value: kotlin.String) {
        @JsonProperty(value = "trainee") trainee("trainee"),
        @JsonProperty(value = "withconvention") withconvention("withconvention"),
        @JsonProperty(value = "accreditated") accreditated("accreditated");
    }
    /**
     * the gender of the healthcare party: male, female, indeterminate, changed, changedToMale, changedToFemale, unknown
     *
     * Values: male,female,indeterminate,changed,changedToMale,changedToFemale,unknown
     */
    enum class Gender(val value: kotlin.String) {
        @JsonProperty(value = "male") male("male"),
        @JsonProperty(value = "female") female("female"),
        @JsonProperty(value = "indeterminate") indeterminate("indeterminate"),
        @JsonProperty(value = "changed") changed("changed"),
        @JsonProperty(value = "changedToMale") changedToMale("changedToMale"),
        @JsonProperty(value = "changedToFemale") changedToFemale("changedToFemale"),
        @JsonProperty(value = "unknown") unknown("unknown");
    }
}

