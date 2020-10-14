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

import io.swagger.client.models.InvoicesBatch
import io.swagger.client.models.MessageDto

/**
 * 
 * @param invoicesBatch 
 * @param message 
 */
data class MessageWithBatch (

    val invoicesBatch: InvoicesBatch? = null,
    val message: MessageDto? = null
) {
}