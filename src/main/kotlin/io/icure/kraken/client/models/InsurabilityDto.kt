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
 * This class represents a coverage of a patient by an insurance during a period or time.
 *
 * @param parameters Insurance extra parameters.
 * @param hospitalisation Is hospitalization covered.
 * @param ambulatory Is outpatient care covered.
 * @param dental Is dental care covered.
 * @param identificationNumber Identification number of the patient at the insurance.
 * @param insuranceId Id of the Insurance.
 * @param startDate Start date of the coverage (YYYYMMDD).
 * @param endDate End date of the coverage (YYYYMMDD).
 * @param titularyId UUID of the contact person who is the policyholder of the insurance (when the patient is covered by the insurance of a third person).
 * @param encryptedSelf The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class InsurabilityDto (

    /* Insurance extra parameters. */
    @field:JsonProperty("parameters")
    val parameters: kotlin.collections.Map<kotlin.String, kotlin.String>,

    /* Is hospitalization covered. */
    @field:JsonProperty("hospitalisation")
    val hospitalisation: kotlin.Boolean? = null,

    /* Is outpatient care covered. */
    @field:JsonProperty("ambulatory")
    val ambulatory: kotlin.Boolean? = null,

    /* Is dental care covered. */
    @field:JsonProperty("dental")
    val dental: kotlin.Boolean? = null,

    /* Identification number of the patient at the insurance. */
    @field:JsonProperty("identificationNumber")
    val identificationNumber: kotlin.String? = null,

    /* Id of the Insurance. */
    @field:JsonProperty("insuranceId")
    val insuranceId: kotlin.String? = null,

    /* Start date of the coverage (YYYYMMDD). */
    @field:JsonProperty("startDate")
    val startDate: kotlin.Long? = null,

    /* End date of the coverage (YYYYMMDD). */
    @field:JsonProperty("endDate")
    val endDate: kotlin.Long? = null,

    /* UUID of the contact person who is the policyholder of the insurance (when the patient is covered by the insurance of a third person). */
    @field:JsonProperty("titularyId")
    val titularyId: kotlin.String? = null,

    /* The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. */
    @field:JsonProperty("encryptedSelf")
    val encryptedSelf: kotlin.String? = null

)

