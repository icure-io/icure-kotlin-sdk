
# AmppDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**orphan** | **kotlin.Boolean** |  | 
**atcs** | [**kotlin.collections.List&lt;AtcDto&gt;**](AtcDto.md) |  | 
**dmpps** | [**kotlin.collections.List&lt;DmppDto&gt;**](DmppDto.md) |  | 
**from** | **kotlin.Long** |  |  [optional]
**to** | **kotlin.Long** |  |  [optional]
**index** | **kotlin.Double** |  |  [optional]
**ctiExtended** | **kotlin.String** |  |  [optional]
**leafletLink** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**spcLink** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**rmaPatientLink** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**rmaProfessionalLink** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**parallelCircuit** | **kotlin.Int** |  |  [optional]
**parallelDistributor** | **kotlin.String** |  |  [optional]
**packMultiplier** | **kotlin.Int** |  |  [optional]
**packAmount** | [**QuantityDto**](QuantityDto.md) |  |  [optional]
**packDisplayValue** | **kotlin.String** |  |  [optional]
**status** | [**inline**](#StatusEnum) |  |  [optional]
**crmLink** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**deliveryModusCode** | **kotlin.String** |  |  [optional]
**deliveryModus** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**deliveryModusSpecificationCode** | **kotlin.String** |  |  [optional]
**deliveryModusSpecification** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**dhpcLink** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**distributorCompany** | [**CompanyDto**](CompanyDto.md) |  |  [optional]
**singleUse** | **kotlin.Boolean** |  |  [optional]
**speciallyRegulated** | **kotlin.Int** |  |  [optional]
**abbreviatedName** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**prescriptionName** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**note** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**posologyNote** | [**SamTextDto**](SamTextDto.md) |  |  [optional]
**noGenericPrescriptionReasons** | [**kotlin.collections.List&lt;SamTextDto&gt;**](SamTextDto.md) |  |  [optional]
**exFactoryPrice** | **kotlin.Double** |  |  [optional]
**reimbursementCode** | **kotlin.Int** |  |  [optional]
**definedDailyDose** | [**QuantityDto**](QuantityDto.md) |  |  [optional]
**officialExFactoryPrice** | **kotlin.Double** |  |  [optional]
**realExFactoryPrice** | **kotlin.Double** |  |  [optional]
**pricingInformationDecisionDate** | **kotlin.Long** |  |  [optional]
**components** | [**kotlin.collections.List&lt;AmppComponentDto&gt;**](AmppComponentDto.md) |  |  [optional]
**commercializations** | [**kotlin.collections.List&lt;CommercializationDto&gt;**](CommercializationDto.md) |  |  [optional]
**supplyProblems** | [**kotlin.collections.List&lt;SupplyProblemDto&gt;**](SupplyProblemDto.md) |  |  [optional]
**vaccineIndicationCodes** | **kotlin.collections.List&lt;kotlin.String&gt;** |  |  [optional]


<a name="StatusEnum"></a>
## Enum: status
Name | Value
---- | -----
status | AUTHORIZED, SUSPENDED, REVOKED



