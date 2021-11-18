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

import io.icure.kraken.client.models.AmppComponentDto
import io.icure.kraken.client.models.AtcDto
import io.icure.kraken.client.models.CommercializationDto
import io.icure.kraken.client.models.CompanyDto
import io.icure.kraken.client.models.DmppDto
import io.icure.kraken.client.models.QuantityDto
import io.icure.kraken.client.models.SamTextDto
import io.icure.kraken.client.models.SupplyProblemDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder


/**
 * 
 *
 * @param orphan 
 * @param atcs 
 * @param dmpps 
 * @param from 
 * @param to 
 * @param index 
 * @param ctiExtended 
 * @param leafletLink 
 * @param spcLink 
 * @param rmaPatientLink 
 * @param rmaProfessionalLink 
 * @param parallelCircuit 
 * @param parallelDistributor 
 * @param packMultiplier 
 * @param packAmount 
 * @param packDisplayValue 
 * @param status 
 * @param crmLink 
 * @param deliveryModusCode 
 * @param deliveryModus 
 * @param deliveryModusSpecificationCode 
 * @param deliveryModusSpecification 
 * @param dhpcLink 
 * @param distributorCompany 
 * @param singleUse 
 * @param speciallyRegulated 
 * @param abbreviatedName 
 * @param prescriptionName 
 * @param note 
 * @param posologyNote 
 * @param noGenericPrescriptionReasons 
 * @param exFactoryPrice 
 * @param reimbursementCode 
 * @param definedDailyDose 
 * @param officialExFactoryPrice 
 * @param realExFactoryPrice 
 * @param pricingInformationDecisionDate 
 * @param components 
 * @param commercializations 
 * @param supplyProblems 
 * @param vaccineIndicationCodes 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class AmppDto (

    @field:JsonProperty("orphan")
    val orphan: kotlin.Boolean,

    @field:JsonProperty("atcs")
    val atcs: kotlin.collections.List<AtcDto> = listOf(),

    @field:JsonProperty("dmpps")
    val dmpps: kotlin.collections.List<DmppDto> = listOf(),

    @field:JsonProperty("from")
    val from: kotlin.Long? = null,

    @field:JsonProperty("to")
    val to: kotlin.Long? = null,

    @field:JsonProperty("index")
    val index: kotlin.Double? = null,

    @field:JsonProperty("ctiExtended")
    val ctiExtended: kotlin.String? = null,

    @field:JsonProperty("leafletLink")
    val leafletLink: SamTextDto? = null,

    @field:JsonProperty("spcLink")
    val spcLink: SamTextDto? = null,

    @field:JsonProperty("rmaPatientLink")
    val rmaPatientLink: SamTextDto? = null,

    @field:JsonProperty("rmaProfessionalLink")
    val rmaProfessionalLink: SamTextDto? = null,

    @field:JsonProperty("parallelCircuit")
    val parallelCircuit: kotlin.Int? = null,

    @field:JsonProperty("parallelDistributor")
    val parallelDistributor: kotlin.String? = null,

    @field:JsonProperty("packMultiplier")
    val packMultiplier: kotlin.Int? = null,

    @field:JsonProperty("packAmount")
    val packAmount: QuantityDto? = null,

    @field:JsonProperty("packDisplayValue")
    val packDisplayValue: kotlin.String? = null,

    @field:JsonProperty("status")
    val status: AmppDto.Status? = null,

    @field:JsonProperty("crmLink")
    val crmLink: SamTextDto? = null,

    @field:JsonProperty("deliveryModusCode")
    val deliveryModusCode: kotlin.String? = null,

    @field:JsonProperty("deliveryModus")
    val deliveryModus: SamTextDto? = null,

    @field:JsonProperty("deliveryModusSpecificationCode")
    val deliveryModusSpecificationCode: kotlin.String? = null,

    @field:JsonProperty("deliveryModusSpecification")
    val deliveryModusSpecification: SamTextDto? = null,

    @field:JsonProperty("dhpcLink")
    val dhpcLink: SamTextDto? = null,

    @field:JsonProperty("distributorCompany")
    val distributorCompany: CompanyDto? = null,

    @field:JsonProperty("singleUse")
    val singleUse: kotlin.Boolean? = null,

    @field:JsonProperty("speciallyRegulated")
    val speciallyRegulated: kotlin.Int? = null,

    @field:JsonProperty("abbreviatedName")
    val abbreviatedName: SamTextDto? = null,

    @field:JsonProperty("prescriptionName")
    val prescriptionName: SamTextDto? = null,

    @field:JsonProperty("note")
    val note: SamTextDto? = null,

    @field:JsonProperty("posologyNote")
    val posologyNote: SamTextDto? = null,

    @field:JsonProperty("noGenericPrescriptionReasons")
    val noGenericPrescriptionReasons: kotlin.collections.List<SamTextDto>? = null,

    @field:JsonProperty("exFactoryPrice")
    val exFactoryPrice: kotlin.Double? = null,

    @field:JsonProperty("reimbursementCode")
    val reimbursementCode: kotlin.Int? = null,

    @field:JsonProperty("definedDailyDose")
    val definedDailyDose: QuantityDto? = null,

    @field:JsonProperty("officialExFactoryPrice")
    val officialExFactoryPrice: kotlin.Double? = null,

    @field:JsonProperty("realExFactoryPrice")
    val realExFactoryPrice: kotlin.Double? = null,

    @field:JsonProperty("pricingInformationDecisionDate")
    val pricingInformationDecisionDate: kotlin.Long? = null,

    @field:JsonProperty("components")
    val components: kotlin.collections.List<AmppComponentDto>? = null,

    @field:JsonProperty("commercializations")
    val commercializations: kotlin.collections.List<CommercializationDto>? = null,

    @field:JsonProperty("supplyProblems")
    val supplyProblems: kotlin.collections.List<SupplyProblemDto>? = null,

    @field:JsonProperty("vaccineIndicationCodes")
    val vaccineIndicationCodes: kotlin.collections.List<kotlin.String>? = null

) {

    /**
     * 
     *
     * Values: aUTHORIZED,sUSPENDED,rEVOKED
     */
    enum class Status(val value: kotlin.String) {
        @JsonProperty(value = "AUTHORIZED") aUTHORIZED("AUTHORIZED"),
        @JsonProperty(value = "SUSPENDED") sUSPENDED("SUSPENDED"),
        @JsonProperty(value = "REVOKED") rEVOKED("REVOKED");
    }
}

