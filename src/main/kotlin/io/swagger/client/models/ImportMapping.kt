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
 * @param lifecycle 
 * @param content 
 * @param type 
 * @param cdItem 
 * @param label 
 */
data class ImportMapping (
    val label: kotlin.collections.Map<kotlin.String, kotlin.String>
,
    val lifecycle: kotlin.String? = null,
    val content: kotlin.String? = null,
    val type: kotlin.String? = null,
    val cdItem: kotlin.String? = null
) {
}