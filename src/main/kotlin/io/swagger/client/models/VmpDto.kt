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

import io.swagger.client.models.CommentedClassificationDto
import io.swagger.client.models.SamTextDto
import io.swagger.client.models.VmpComponentDto
import io.swagger.client.models.VmpGroupStubDto
import io.swagger.client.models.VtmDto
import io.swagger.client.models.WadaDto

/**
 * 
 * @param id 
 * @param rev 
 * @param deletionDate 
 * @param from 
 * @param to 
 * @param code 
 * @param vmpGroup 
 * @param name 
 * @param abbreviation 
 * @param vtm 
 * @param wadas 
 * @param components 
 * @param commentedClassifications 
 */
data class VmpDto (
    val id: kotlin.String
,
    val rev: kotlin.String? = null,
    val deletionDate: kotlin.Long? = null,
    val from: kotlin.Long? = null,
    val to: kotlin.Long? = null,
    val code: kotlin.String? = null,
    val vmpGroup: VmpGroupStubDto? = null,
    val name: SamTextDto? = null,
    val abbreviation: SamTextDto? = null,
    val vtm: VtmDto? = null,
    val wadas: kotlin.Array<WadaDto>? = null,
    val components: kotlin.Array<VmpComponentDto>? = null,
    val commentedClassifications: kotlin.Array<CommentedClassificationDto>? = null
) {
}