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
 * @param groupId 
 * @param groupName 
 * @param userId 
 * @param login 
 * @param name 
 * @param email 
 * @param phone 
 * @param patientId 
 * @param healthcarePartyId 
 * @param deviceId 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class UserGroupDto (

    @field:JsonProperty("groupId")
    val groupId: kotlin.String? = null,

    @field:JsonProperty("groupName")
    val groupName: kotlin.String? = null,

    @field:JsonProperty("userId")
    val userId: kotlin.String? = null,

    @field:JsonProperty("login")
    val login: kotlin.String? = null,

    @field:JsonProperty("name")
    val name: kotlin.String? = null,

    @field:JsonProperty("email")
    val email: kotlin.String? = null,

    @field:JsonProperty("phone")
    val phone: kotlin.String? = null,

    @field:JsonProperty("patientId")
    val patientId: kotlin.String? = null,

    @field:JsonProperty("healthcarePartyId")
    val healthcarePartyId: kotlin.String? = null,

    @field:JsonProperty("deviceId")
    val deviceId: kotlin.String? = null

)

