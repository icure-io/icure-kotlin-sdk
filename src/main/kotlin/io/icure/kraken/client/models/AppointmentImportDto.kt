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
 * 
 *
 * @param comments 
 * @param externalCustomerId 
 * @param customerId 
 * @param customerComments 
 * @param title 
 * @param endTime 
 * @param startTime 
 * @param type 
 * @param appointmentTypeId 
 * @param ownerRef 
 * @param customerName 
 * @param customerFirstname 
 * @param customerEmail 
 * @param city 
 * @param postcode 
 * @param street 
 * @param sex 
 * @param externalId 
 * @param customerBirthDate 
 * @param customerGsm 
 * @param customerFixPhone 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class AppointmentImportDto (

    @field:JsonProperty("comments")
    val comments: kotlin.String? = null,

    @field:JsonProperty("externalCustomerId")
    val externalCustomerId: kotlin.String? = null,

    @field:JsonProperty("customerId")
    val customerId: kotlin.String? = null,

    @field:JsonProperty("customerComments")
    val customerComments: kotlin.String? = null,

    @field:JsonProperty("title")
    val title: kotlin.String? = null,

    @field:JsonProperty("endTime")
    val endTime: java.time.OffsetDateTime? = null,

    @field:JsonProperty("startTime")
    val startTime: java.time.OffsetDateTime? = null,

    @field:JsonProperty("type")
    val type: kotlin.String? = null,

    @field:JsonProperty("appointmentTypeId")
    val appointmentTypeId: kotlin.String? = null,

    @field:JsonProperty("ownerRef")
    val ownerRef: kotlin.String? = null,

    @field:JsonProperty("customerName")
    val customerName: kotlin.String? = null,

    @field:JsonProperty("customerFirstname")
    val customerFirstname: kotlin.String? = null,

    @field:JsonProperty("customerEmail")
    val customerEmail: kotlin.String? = null,

    @field:JsonProperty("city")
    val city: kotlin.String? = null,

    @field:JsonProperty("postcode")
    val postcode: kotlin.String? = null,

    @field:JsonProperty("street")
    val street: kotlin.String? = null,

    @field:JsonProperty("sex")
    val sex: kotlin.String? = null,

    @field:JsonProperty("externalId")
    val externalId: kotlin.String? = null,

    @field:JsonProperty("customerBirthDate")
    val customerBirthDate: java.time.OffsetDateTime? = null,

    @field:JsonProperty("customerGsm")
    val customerGsm: kotlin.String? = null,

    @field:JsonProperty("customerFixPhone")
    val customerFixPhone: kotlin.String? = null

)

