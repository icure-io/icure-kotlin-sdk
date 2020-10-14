/**
 * iCure Cloud API Documentation
 * Spring shop sample application
 *
 * OpenAPI spec version: v0.0.1
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */
package io.swagger.client.models

import io.swagger.client.models.MimeAttachmentDto

/**
 * 
 * @param attachments 
 * @param destination 
 * @param destinationIsNotPatient 
 * @param destinationName 
 * @param sendCopyToSender 
 * @param senderName 
 * @param replyToEmail 
 * @param content 
 * @param messageId 
 * @param patientId 
 * @param senderId 
 * @param subject 
 * @param type 
 */
data class EmailOrSmsMessageDto (
    val attachments: kotlin.Array<MimeAttachmentDto>,
    val destinationIsNotPatient: kotlin.Boolean,
    val sendCopyToSender: kotlin.Boolean
,
    val destination: kotlin.String? = null,
    val destinationName: kotlin.String? = null,
    val senderName: kotlin.String? = null,
    val replyToEmail: kotlin.String? = null,
    val content: kotlin.String? = null,
    val messageId: kotlin.String? = null,
    val patientId: kotlin.String? = null,
    val senderId: kotlin.String? = null,
    val subject: kotlin.String? = null,
    val type: EmailOrSmsMessageDto.Type? = null
) {
    /**
    * 
    * Values: eMAIL,sMS
    */
    enum class Type(val value: kotlin.String){
        eMAIL("EMAIL"),
        sMS("SMS");
    }
}