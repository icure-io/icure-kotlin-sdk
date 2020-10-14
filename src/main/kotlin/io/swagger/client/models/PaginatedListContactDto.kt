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

import io.swagger.client.models.ContactDto
import io.swagger.client.models.PaginatedDocumentKeyIdPairObject

/**
 * 
 * @param pageSize 
 * @param totalSize 
 * @param rows 
 * @param nextKeyPair 
 */
data class PaginatedListContactDto (
    val pageSize: kotlin.Int,
    val totalSize: kotlin.Int,
    val rows: kotlin.Array<ContactDto>
,
    val nextKeyPair: PaginatedDocumentKeyIdPairObject? = null
) {
}