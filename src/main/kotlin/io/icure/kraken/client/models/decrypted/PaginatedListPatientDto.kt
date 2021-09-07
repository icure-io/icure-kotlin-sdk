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
package io.icure.kraken.client.models.decrypted

import io.icure.kraken.client.models.PaginatedDocumentKeyIdPairObject
import io.icure.kraken.client.models.decrypted.PatientDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 *
 *
 * @param pageSize
 * @param totalSize
 * @param rows
 * @param nextKeyPair
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class PaginatedListPatientDto (

    @field:JsonProperty("pageSize")
    val pageSize: kotlin.Int,

    @field:JsonProperty("totalSize")
    val totalSize: kotlin.Int,

    @field:JsonProperty("rows")
    val rows: kotlin.collections.List<PatientDto> = listOf(),

    @field:JsonProperty("nextKeyPair")
    val nextKeyPair: PaginatedDocumentKeyIdPairObject? = null

)

