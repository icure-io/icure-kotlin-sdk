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

import io.swagger.client.models.FormColumn

/**
 * 
 * @param icon 
 * @param title 
 * @param columns 
 * @param formColumns 
 */
data class FormSection (

    val icon: kotlin.String? = null,
    val title: kotlin.String? = null,
    val columns: kotlin.Int? = null,
    val formColumns: kotlin.Array<FormColumn>? = null
) {
}