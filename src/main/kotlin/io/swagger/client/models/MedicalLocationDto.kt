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

import io.swagger.client.models.AddressDto

/**
 * 
 * @param id 
 * @param rev 
 * @param deletionDate 
 * @param name 
 * @param description 
 * @param responsible 
 * @param guardPost 
 * @param cbe 
 * @param bic 
 * @param bankAccount 
 * @param nihii 
 * @param ssin 
 * @param address 
 * @param agendaIds 
 * @param options 
 */
data class MedicalLocationDto (
    val id: kotlin.String,
    val agendaIds: kotlin.Array<kotlin.String>,
    val options: kotlin.collections.Map<kotlin.String, kotlin.String>
,
    val rev: kotlin.String? = null,
    val deletionDate: kotlin.Long? = null,
    val name: kotlin.String? = null,
    val description: kotlin.String? = null,
    val responsible: kotlin.String? = null,
    val guardPost: kotlin.Boolean? = null,
    val cbe: kotlin.String? = null,
    val bic: kotlin.String? = null,
    val bankAccount: kotlin.String? = null,
    val nihii: kotlin.String? = null,
    val ssin: kotlin.String? = null,
    val address: AddressDto? = null
) {
}