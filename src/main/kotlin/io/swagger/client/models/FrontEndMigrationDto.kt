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
 * @param name 
 * @param startDate 
 * @param endDate 
 * @param status 
 * @param logs 
 * @param userId 
 * @param startKey 
 * @param startKeyDocId 
 * @param processCount 
 */
data class FrontEndMigrationDto (
    val id: kotlin.String
,
    val rev: kotlin.String? = null,
    val deletionDate: kotlin.Long? = null,
    val name: kotlin.String? = null,
    val startDate: kotlin.Long? = null,
    val endDate: kotlin.Long? = null,
    val status: FrontEndMigrationDto.Status? = null,
    val logs: kotlin.String? = null,
    val userId: kotlin.String? = null,
    val startKey: kotlin.String? = null,
    val startKeyDocId: kotlin.String? = null,
    val processCount: kotlin.Long? = null
) {
    /**
    * 
    * Values: sTARTED,eRROR,sUCCESS
    */
    enum class Status(val value: kotlin.String){
        sTARTED("STARTED"),
        eRROR("ERROR"),
        sUCCESS("SUCCESS");
    }
}