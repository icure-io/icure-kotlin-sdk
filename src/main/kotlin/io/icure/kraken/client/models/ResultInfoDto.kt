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
import io.icure.kraken.client.models.ServiceDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param codes 
 * @param services 
 * @param ssin 
 * @param lastName 
 * @param firstName 
 * @param dateOfBirth 
 * @param sex 
 * @param documentId 
 * @param protocol 
 * @param complete 
 * @param demandDate 
 * @param labo 
 * @param engine 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class ResultInfoDto (

    @field:JsonProperty("codes")
    val codes: kotlin.collections.List<CodeStubDto> = emptyList(),

    @field:JsonProperty("services")
    val services: kotlin.collections.List<ServiceDto> = emptyList(),

    @field:JsonProperty("ssin")
    val ssin: kotlin.String? = null,

    @field:JsonProperty("lastName")
    val lastName: kotlin.String? = null,

    @field:JsonProperty("firstName")
    val firstName: kotlin.String? = null,

    @field:JsonProperty("dateOfBirth")
    val dateOfBirth: kotlin.Long? = null,

    @field:JsonProperty("sex")
    val sex: kotlin.String? = null,

    @field:JsonProperty("documentId")
    val documentId: kotlin.String? = null,

    @field:JsonProperty("protocol")
    val protocol: kotlin.String? = null,

    @field:JsonProperty("complete")
    val complete: kotlin.Boolean? = null,

    @field:JsonProperty("demandDate")
    val demandDate: kotlin.Long? = null,

    @field:JsonProperty("labo")
    val labo: kotlin.String? = null,

    @field:JsonProperty("engine")
    val engine: kotlin.String? = null

)

