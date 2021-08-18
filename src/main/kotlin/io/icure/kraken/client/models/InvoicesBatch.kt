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

import io.icure.kraken.client.models.EfactInvoice
import io.icure.kraken.client.models.InvoiceSender

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param invoicingYear 
 * @param invoicingMonth 
 * @param invoices 
 * @param fileRef 
 * @param batchRef 
 * @param ioFederationCode 
 * @param uniqueSendNumber 
 * @param sender 
 * @param numericalRef 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class InvoicesBatch (

    @field:JsonProperty("invoicingYear")
    val invoicingYear: kotlin.Int = 0,

    @field:JsonProperty("invoicingMonth")
    val invoicingMonth: kotlin.Int = 0,

    @field:JsonProperty("invoices")
    val invoices: kotlin.collections.List<EfactInvoice> = listOf(),

    @field:JsonProperty("fileRef")
    val fileRef: kotlin.String? = null,

    @field:JsonProperty("batchRef")
    val batchRef: kotlin.String? = null,

    @field:JsonProperty("ioFederationCode")
    val ioFederationCode: kotlin.String? = null,

    @field:JsonProperty("uniqueSendNumber")
    val uniqueSendNumber: kotlin.Long? = null,

    @field:JsonProperty("sender")
    val sender: InvoiceSender? = null,

    @field:JsonProperty("numericalRef")
    val numericalRef: kotlin.Long? = null

)

