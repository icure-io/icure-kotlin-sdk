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


import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * Financial information (Bank, bank account) used to reimburse the patient.
 *
 * @param preferredFiiForPartners 
 * @param name 
 * @param key 
 * @param bankAccount 
 * @param bic 
 * @param proxyBankAccount 
 * @param proxyBic 
 * @param encryptedSelf The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class FinancialInstitutionInformationDto (

    @field:JsonProperty("preferredFiiForPartners")
    val preferredFiiForPartners: kotlin.collections.List<kotlin.String>,

    @field:JsonProperty("name")
    val name: kotlin.String? = null,

    @field:JsonProperty("key")
    val key: kotlin.String? = null,

    @field:JsonProperty("bankAccount")
    val bankAccount: kotlin.String? = null,

    @field:JsonProperty("bic")
    val bic: kotlin.String? = null,

    @field:JsonProperty("proxyBankAccount")
    val proxyBankAccount: kotlin.String? = null,

    @field:JsonProperty("proxyBic")
    val proxyBic: kotlin.String? = null,

    /* The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. */
    @field:JsonProperty("encryptedSelf")
    val encryptedSelf: kotlin.String? = null

)

