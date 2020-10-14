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
 * @param planninfForAnyDoctor 
 * @param planningForDelegate 
 * @param planningForPatientDoctor 
 * @param planningForMe 
 * @param codedDelayInDays 
 * @param repetitions 
 * @param repetitionsUnit 
 * @param descr 
 */
data class FormPlanning (

    val planninfForAnyDoctor: kotlin.Boolean? = null,
    val planningForDelegate: kotlin.Boolean? = null,
    val planningForPatientDoctor: kotlin.Boolean? = null,
    val planningForMe: kotlin.Boolean? = null,
    val codedDelayInDays: kotlin.Int? = null,
    val repetitions: kotlin.Int? = null,
    val repetitionsUnit: kotlin.Int? = null,
    val descr: kotlin.String? = null
) {
}