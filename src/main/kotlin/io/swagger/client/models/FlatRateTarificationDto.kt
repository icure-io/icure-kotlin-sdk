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

import io.swagger.client.models.ValorisationDto

/**
 * 
 * @param code 
 * @param flatRateType 
 * @param label 
 * @param valorisations 
 * @param encryptedSelf 
 */
data class FlatRateTarificationDto (
    val valorisations: kotlin.Array<ValorisationDto>
,
    val code: kotlin.String? = null,
    val flatRateType: FlatRateTarificationDto.FlatRateType? = null,
    val label: kotlin.collections.Map<kotlin.String, kotlin.String>? = null,
    val encryptedSelf: kotlin.String? = null
) {
    /**
    * 
    * Values: physician,physiotherapist,nurse,ptd
    */
    enum class FlatRateType(val value: kotlin.String){
        physician("physician"),
        physiotherapist("physiotherapist"),
        nurse("nurse"),
        ptd("ptd");
    }
}