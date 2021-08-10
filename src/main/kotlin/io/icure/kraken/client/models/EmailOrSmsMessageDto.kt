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

import io.icure.kraken.client.models.MimeAttachmentDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param attachments 
 * @param destinationIsNotPatient 
 * @param sendCopyToSender 
 * @param destination 
 * @param destinationName 
 * @param senderName 
 * @param replyToEmail 
 * @param content 
 * @param messageId 
 * @param patientId 
 * @param senderId 
 * @param subject 
 * @param type 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class EmailOrSmsMessageDto (

    @field:JsonProperty("attachments")
    val attachments: kotlin.collections.List<MimeAttachmentDto>,

    @field:JsonProperty("destinationIsNotPatient")
    val destinationIsNotPatient: kotlin.Boolean,

    @field:JsonProperty("sendCopyToSender")
    val sendCopyToSender: kotlin.Boolean,

    @field:JsonProperty("destination")
    val destination: kotlin.String? = null,

    @field:JsonProperty("destinationName")
    val destinationName: kotlin.String? = null,

    @field:JsonProperty("senderName")
    val senderName: kotlin.String? = null,

    @field:JsonProperty("replyToEmail")
    val replyToEmail: kotlin.String? = null,

    @field:JsonProperty("content")
    val content: kotlin.String? = null,

    @field:JsonProperty("messageId")
    val messageId: kotlin.String? = null,

    @field:JsonProperty("patientId")
    val patientId: kotlin.String? = null,

    @field:JsonProperty("senderId")
    val senderId: kotlin.String? = null,

    @field:JsonProperty("subject")
    val subject: kotlin.String? = null,

    @field:JsonProperty("type")
    val type: EmailOrSmsMessageDto.Type? = null

) {

    /**
     * 
     *
     * Values: eMAIL,sMS
     */
    enum class Type(val value: kotlin.String) {
        @JsonProperty(value = "EMAIL") eMAIL("EMAIL"),
        @JsonProperty(value = "SMS") sMS("SMS");
    }
}

