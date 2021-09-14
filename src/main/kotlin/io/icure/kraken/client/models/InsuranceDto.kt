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

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param id 
 * @param name 
 * @param privateInsurance 
 * @param hospitalisationInsurance 
 * @param ambulatoryInsurance 
 * @param address 
 * @param rev 
 * @param deletionDate hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called.
 * @param code 
 * @param agreementNumber 
 * @param parent 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class InsuranceDto (

    @field:JsonProperty("id")
    val id: kotlin.String,

    @field:JsonProperty("name")
    val name: kotlin.collections.Map<kotlin.String, kotlin.String> = mapOf(),

    @field:JsonProperty("privateInsurance")
    val privateInsurance: kotlin.Boolean,

    @field:JsonProperty("hospitalisationInsurance")
    val hospitalisationInsurance: kotlin.Boolean,

    @field:JsonProperty("ambulatoryInsurance")
    val ambulatoryInsurance: kotlin.Boolean,

    @field:JsonProperty("address")
    val address: AddressDto,

    @field:JsonProperty("rev")
    val rev: kotlin.String? = null,

    /* hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. */
    @field:JsonProperty("deletionDate")
    val deletionDate: kotlin.Long? = null,

    @field:JsonProperty("code")
    val code: kotlin.String? = null,

    @field:JsonProperty("agreementNumber")
    val agreementNumber: kotlin.String? = null,

    @field:JsonProperty("parent")
    val parent: kotlin.String? = null

)

