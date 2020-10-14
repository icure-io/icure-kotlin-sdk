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
import io.swagger.client.models.DelegationDto

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
 * @param openingDate 
 * @param groupId 
 * @param descr 
 * @param formTemplateId 
 * @param contactId 
 * @param healthElementId 
 * @param planOfActionId 
 * @param parent 
 * @param secretForeignKeys 
 * @param cryptedForeignKeys 
 * @param delegations 
 * @param encryptionKeys 
 * @param encryptedSelf 
 */
data class FormDto (
    val id: kotlin.String,
    val tags: kotlin.Array<CodeStubDto>,
    val codes: kotlin.Array<CodeStubDto>,
    val secretForeignKeys: kotlin.Array<kotlin.String>,
    val cryptedForeignKeys: kotlin.collections.Map<kotlin.String, kotlin.Array<DelegationDto>>,
    val delegations: kotlin.collections.Map<kotlin.String, kotlin.Array<DelegationDto>>,
    val encryptionKeys: kotlin.collections.Map<kotlin.String, kotlin.Array<DelegationDto>>
,
    val rev: kotlin.String? = null,
    val created: kotlin.Long? = null,
    val modified: kotlin.Long? = null,
    val author: kotlin.String? = null,
    val responsible: kotlin.String? = null,
    val medicalLocationId: kotlin.String? = null,
    val endOfLife: kotlin.Long? = null,
    val deletionDate: kotlin.Long? = null,
    val openingDate: kotlin.Long? = null,
    val groupId: kotlin.String? = null,
    val descr: kotlin.String? = null,
    val formTemplateId: kotlin.String? = null,
    val contactId: kotlin.String? = null,
    val healthElementId: kotlin.String? = null,
    val planOfActionId: kotlin.String? = null,
    val parent: kotlin.String? = null,
    val encryptedSelf: kotlin.String? = null
) {
}