/**
 * iCure Data Stack API Documentation
 *
 * The iCure Data Stack Application API is the native interface to iCure.
 *
 * The version of the OpenAPI document: v2
 * 
 *
 * Please note:
 * This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * Do not edit this file manually.
 */
package io.icure.kraken.client.models

import io.icure.kraken.client.models.CopaymentDto
import io.icure.kraken.client.models.PricingDto
import io.icure.kraken.client.models.ReimbursementCriterionDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param from 
 * @param to 
 * @param deliveryEnvironment 
 * @param code 
 * @param codeType 
 * @param multiple 
 * @param temporary 
 * @param reference 
 * @param legalReferencePath 
 * @param flatRateSystem 
 * @param reimbursementBasePrice 
 * @param referenceBasePrice 
 * @param copaymentSupplement 
 * @param pricingUnit 
 * @param pricingSlice 
 * @param reimbursementCriterion 
 * @param copayments 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class ReimbursementDto (

    @field:JsonProperty("from")
    val from: kotlin.Long? = null,

    @field:JsonProperty("to")
    val to: kotlin.Long? = null,

    @field:JsonProperty("deliveryEnvironment")
    val deliveryEnvironment: ReimbursementDto.DeliveryEnvironment? = null,

    @field:JsonProperty("code")
    val code: kotlin.String? = null,

    @field:JsonProperty("codeType")
    val codeType: ReimbursementDto.CodeType? = null,

    @field:JsonProperty("multiple")
    val multiple: ReimbursementDto.Multiple? = null,

    @field:JsonProperty("temporary")
    val temporary: kotlin.Boolean? = null,

    @field:JsonProperty("reference")
    val reference: kotlin.Boolean? = null,

    @field:JsonProperty("legalReferencePath")
    val legalReferencePath: kotlin.String? = null,

    @field:JsonProperty("flatRateSystem")
    val flatRateSystem: kotlin.Boolean? = null,

    @field:JsonProperty("reimbursementBasePrice")
    val reimbursementBasePrice: java.math.BigDecimal? = null,

    @field:JsonProperty("referenceBasePrice")
    val referenceBasePrice: java.math.BigDecimal? = null,

    @field:JsonProperty("copaymentSupplement")
    val copaymentSupplement: java.math.BigDecimal? = null,

    @field:JsonProperty("pricingUnit")
    val pricingUnit: PricingDto? = null,

    @field:JsonProperty("pricingSlice")
    val pricingSlice: PricingDto? = null,

    @field:JsonProperty("reimbursementCriterion")
    val reimbursementCriterion: ReimbursementCriterionDto? = null,

    @field:JsonProperty("copayments")
    val copayments: kotlin.collections.List<CopaymentDto>? = null

) {

    /**
     * 
     *
     * Values: p,a,h,r
     */
    enum class DeliveryEnvironment(val value: kotlin.String) {
        @JsonProperty(value = "P") p("P"),
        @JsonProperty(value = "A") a("A"),
        @JsonProperty(value = "H") h("H"),
        @JsonProperty(value = "R") r("R");
    }
    /**
     * 
     *
     * Values: cNK,pSEUDO
     */
    enum class CodeType(val value: kotlin.String) {
        @JsonProperty(value = "CNK") cNK("CNK"),
        @JsonProperty(value = "PSEUDO") pSEUDO("PSEUDO");
    }
    /**
     * 
     *
     * Values: m,v
     */
    enum class Multiple(val value: kotlin.String) {
        @JsonProperty(value = "M") m("M"),
        @JsonProperty(value = "V") v("V");
    }
}

