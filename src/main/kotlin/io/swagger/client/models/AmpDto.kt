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

import io.swagger.client.models.AmpComponentDto
import io.swagger.client.models.AmppDto
import io.swagger.client.models.CompanyDto
import io.swagger.client.models.SamTextDto
import io.swagger.client.models.VmpStubDto

/**
 * 
 * @param id 
 * @param rev 
 * @param deletionDate 
 * @param from 
 * @param to 
 * @param code 
 * @param vmp 
 * @param officialName 
 * @param status 
 * @param name 
 * @param blackTriangle 
 * @param medicineType 
 * @param company 
 * @param abbreviatedName 
 * @param proprietarySuffix 
 * @param prescriptionName 
 * @param ampps 
 * @param components 
 */
data class AmpDto (
    val id: kotlin.String,
    val blackTriangle: kotlin.Boolean,
    val ampps: kotlin.Array<AmppDto>,
    val components: kotlin.Array<AmpComponentDto>
,
    val rev: kotlin.String? = null,
    val deletionDate: kotlin.Long? = null,
    val from: kotlin.Long? = null,
    val to: kotlin.Long? = null,
    val code: kotlin.String? = null,
    val vmp: VmpStubDto? = null,
    val officialName: kotlin.String? = null,
    val status: AmpDto.Status? = null,
    val name: SamTextDto? = null,
    val medicineType: AmpDto.MedicineType? = null,
    val company: CompanyDto? = null,
    val abbreviatedName: SamTextDto? = null,
    val proprietarySuffix: SamTextDto? = null,
    val prescriptionName: SamTextDto? = null
) {
    /**
    * 
    * Values: aUTHORIZED,sUSPENDED,rEVOKED
    */
    enum class Status(val value: kotlin.String){
        aUTHORIZED("AUTHORIZED"),
        sUSPENDED("SUSPENDED"),
        rEVOKED("REVOKED");
    }
    /**
    * 
    * Values: aLLOPATHIC,hOMEOPATHIC
    */
    enum class MedicineType(val value: kotlin.String){
        aLLOPATHIC("ALLOPATHIC"),
        hOMEOPATHIC("HOMEOPATHIC");
    }
}