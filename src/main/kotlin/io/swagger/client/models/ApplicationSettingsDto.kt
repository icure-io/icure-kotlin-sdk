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

import io.swagger.client.models.CodeStubDto

/**
 * 
 * @param id 
 * @param rev 
 * @param created 
 * @param modified 
 * @param author 
 * @param responsible 
 * @param medicalLocationId 
 * @param tags 
 * @param codes 
 * @param endOfLife 
 * @param deletionDate 
 * @param settings 
 */
data class ApplicationSettingsDto (
    val id: kotlin.String,
    val tags: kotlin.Array<CodeStubDto>,
    val codes: kotlin.Array<CodeStubDto>,
    val settings: kotlin.collections.Map<kotlin.String, kotlin.String>
,
    val rev: kotlin.String? = null,
    val created: kotlin.Long? = null,
    val modified: kotlin.Long? = null,
    val author: kotlin.String? = null,
    val responsible: kotlin.String? = null,
    val medicalLocationId: kotlin.String? = null,
    val endOfLife: kotlin.Long? = null,
    val deletionDate: kotlin.Long? = null
) {
}