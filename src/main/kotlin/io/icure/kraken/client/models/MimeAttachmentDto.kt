/**
 * iCure Cloud API Documentation
 *
 * Spring shop sample application
 *
 * The version of the OpenAPI document: v0.0.1
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
 * @param `data` 
 * @param fileName 
 * @param mimeType 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class MimeAttachmentDto (

    @field:JsonProperty("data")
    val `data`: kotlin.collections.List<kotlin.ByteArray>? = null,

    @field:JsonProperty("fileName")
    val fileName: kotlin.String? = null,

    @field:JsonProperty("mimeType")
    val mimeType: kotlin.String? = null

)

