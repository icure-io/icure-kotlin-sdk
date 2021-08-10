/**
* iCure Cloud API Documentation
* Spring shop sample application
*
* The version of the OpenAPI document: v0.0.1
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
package io.icure.kraken.client.models

import io.icure.kraken.client.models.EIDItem

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param codeNomenclature 
 * @param units 
 * @param reimbursedAmount 
 * @param patientFee 
 * @param doctorSupplement 
 * @param dateCode 
 * @param relatedCode 
 * @param eidItem 
 * @param insuranceRef 
 * @param insuranceRefDate 
 * @param sideCode 
 * @param timeOfDay 
 * @param override3rdPayerCode 
 * @param gnotionNihii 
 * @param derogationMaxNumber 
 * @param prescriberNorm 
 * @param prescriberNihii 
 * @param prescriptionDate 
 * @param personalInterventionCoveredByThirdPartyCode 
 * @param doctorIdentificationNumber 
 * @param invoiceRef 
 * @param percentNorm 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class InvoiceItem (

    @field:JsonProperty("codeNomenclature")
    val codeNomenclature: kotlin.Long,

    @field:JsonProperty("units")
    val units: kotlin.Int,

    @field:JsonProperty("reimbursedAmount")
    val reimbursedAmount: kotlin.Long,

    @field:JsonProperty("patientFee")
    val patientFee: kotlin.Long,

    @field:JsonProperty("doctorSupplement")
    val doctorSupplement: kotlin.Long,

    @field:JsonProperty("dateCode")
    val dateCode: kotlin.Long? = null,

    @field:JsonProperty("relatedCode")
    val relatedCode: kotlin.Long? = null,

    @field:JsonProperty("eidItem")
    val eidItem: EIDItem? = null,

    @field:JsonProperty("insuranceRef")
    val insuranceRef: kotlin.String? = null,

    @field:JsonProperty("insuranceRefDate")
    val insuranceRefDate: kotlin.Long? = null,

    @field:JsonProperty("sideCode")
    val sideCode: InvoiceItem.SideCode? = null,

    @field:JsonProperty("timeOfDay")
    val timeOfDay: InvoiceItem.TimeOfDay? = null,

    @field:JsonProperty("override3rdPayerCode")
    val override3rdPayerCode: kotlin.Int? = null,

    @field:JsonProperty("gnotionNihii")
    val gnotionNihii: kotlin.String? = null,

    @field:JsonProperty("derogationMaxNumber")
    val derogationMaxNumber: InvoiceItem.DerogationMaxNumber? = null,

    @field:JsonProperty("prescriberNorm")
    val prescriberNorm: InvoiceItem.PrescriberNorm? = null,

    @field:JsonProperty("prescriberNihii")
    val prescriberNihii: kotlin.String? = null,

    @field:JsonProperty("prescriptionDate")
    val prescriptionDate: kotlin.Long? = null,

    @field:JsonProperty("personalInterventionCoveredByThirdPartyCode")
    val personalInterventionCoveredByThirdPartyCode: kotlin.Int? = null,

    @field:JsonProperty("doctorIdentificationNumber")
    val doctorIdentificationNumber: kotlin.String? = null,

    @field:JsonProperty("invoiceRef")
    val invoiceRef: kotlin.String? = null,

    @field:JsonProperty("percentNorm")
    val percentNorm: InvoiceItem.PercentNorm? = null

) {

    /**
     * 
     *
     * Values: none,left,right
     */
    enum class SideCode(val value: kotlin.String) {
        @JsonProperty(value = "None") none("None"),
        @JsonProperty(value = "Left") left("Left"),
        @JsonProperty(value = "Right") right("Right");
    }
    /**
     * 
     *
     * Values: other,night,weekend,bankholiday,urgent
     */
    enum class TimeOfDay(val value: kotlin.String) {
        @JsonProperty(value = "Other") other("Other"),
        @JsonProperty(value = "Night") night("Night"),
        @JsonProperty(value = "Weekend") weekend("Weekend"),
        @JsonProperty(value = "Bankholiday") bankholiday("Bankholiday"),
        @JsonProperty(value = "Urgent") urgent("Urgent");
    }
    /**
     * 
     *
     * Values: other,derogationMaxNumber,otherPrescription,secondPrestationOfDay,thirdAndNextPrestationOfDay
     */
    enum class DerogationMaxNumber(val value: kotlin.String) {
        @JsonProperty(value = "Other") other("Other"),
        @JsonProperty(value = "DerogationMaxNumber") derogationMaxNumber("DerogationMaxNumber"),
        @JsonProperty(value = "OtherPrescription") otherPrescription("OtherPrescription"),
        @JsonProperty(value = "SecondPrestationOfDay") secondPrestationOfDay("SecondPrestationOfDay"),
        @JsonProperty(value = "ThirdAndNextPrestationOfDay") thirdAndNextPrestationOfDay("ThirdAndNextPrestationOfDay");
    }
    /**
     * 
     *
     * Values: none,onePrescriber,selfPrescriber,addedCode,manyPrescribers
     */
    enum class PrescriberNorm(val value: kotlin.String) {
        @JsonProperty(value = "None") none("None"),
        @JsonProperty(value = "OnePrescriber") onePrescriber("OnePrescriber"),
        @JsonProperty(value = "SelfPrescriber") selfPrescriber("SelfPrescriber"),
        @JsonProperty(value = "AddedCode") addedCode("AddedCode"),
        @JsonProperty(value = "ManyPrescribers") manyPrescribers("ManyPrescribers");
    }
    /**
     * 
     *
     * Values: none,surgicalAid1,surgicalAid2,reducedFee,ah1n1,halfPriceSecondAct,invoiceException,forInformation
     */
    enum class PercentNorm(val value: kotlin.String) {
        @JsonProperty(value = "None") none("None"),
        @JsonProperty(value = "SurgicalAid1") surgicalAid1("SurgicalAid1"),
        @JsonProperty(value = "SurgicalAid2") surgicalAid2("SurgicalAid2"),
        @JsonProperty(value = "ReducedFee") reducedFee("ReducedFee"),
        @JsonProperty(value = "Ah1n1") ah1n1("Ah1n1"),
        @JsonProperty(value = "HalfPriceSecondAct") halfPriceSecondAct("HalfPriceSecondAct"),
        @JsonProperty(value = "InvoiceException") invoiceException("InvoiceException"),
        @JsonProperty(value = "ForInformation") forInformation("ForInformation");
    }
}

