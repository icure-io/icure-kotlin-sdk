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


/**
 * 
 * @param id 
 * @param rev 
 * @param deletionDate 
 * @param version 
 * @param date 
 */
data class SamVersionDto (
    val id: kotlin.String
,
    val rev: kotlin.String? = null,
    val deletionDate: kotlin.Long? = null,
    val version: kotlin.String? = null,
    val date: kotlin.Int? = null
) {
}