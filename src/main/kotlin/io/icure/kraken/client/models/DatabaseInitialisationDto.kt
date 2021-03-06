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

import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.ReplicationDto
import io.icure.kraken.client.models.UserDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * initialisationData is an object that contains the initial replications (target must be an internalTarget of value base, healthdata or patient) and the users and healthcare parties to be created
 *
 * @param users 
 * @param healthcareParties 
 * @param replication 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class DatabaseInitialisationDto (

    @field:JsonProperty("users")
    val users: kotlin.collections.List<UserDto>? = null,

    @field:JsonProperty("healthcareParties")
    val healthcareParties: kotlin.collections.List<HealthcarePartyDto>? = null,

    @field:JsonProperty("replication")
    val replication: ReplicationDto? = null

)

