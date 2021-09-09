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

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param intendedcds 
 * @param deliveredcds 
 * @param intendedname 
 * @param deliveredname 
 * @param productId 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class MedicinalproductDto (

    @field:JsonProperty("intendedcds")
    val intendedcds: kotlin.collections.List<CodeStubDto> = listOf(),

    @field:JsonProperty("deliveredcds")
    val deliveredcds: kotlin.collections.List<CodeStubDto> = listOf(),

    @field:JsonProperty("intendedname")
    val intendedname: kotlin.String? = null,

    @field:JsonProperty("deliveredname")
    val deliveredname: kotlin.String? = null,

    @field:JsonProperty("productId")
    val productId: kotlin.String? = null

)

