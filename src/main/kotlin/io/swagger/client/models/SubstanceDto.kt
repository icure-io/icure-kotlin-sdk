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

import io.swagger.client.models.SamTextDto
import io.swagger.client.models.StandardSubstanceDto

/**
 * 
 * @param id 
 * @param rev 
 * @param deletionDate 
 * @param code 
 * @param chemicalForm 
 * @param name 
 * @param note 
 * @param standardSubstances 
 */
data class SubstanceDto (
    val id: kotlin.String
,
    val rev: kotlin.String? = null,
    val deletionDate: kotlin.Long? = null,
    val code: kotlin.String? = null,
    val chemicalForm: kotlin.String? = null,
    val name: SamTextDto? = null,
    val note: SamTextDto? = null,
    val standardSubstances: kotlin.Array<StandardSubstanceDto>? = null
) {
}