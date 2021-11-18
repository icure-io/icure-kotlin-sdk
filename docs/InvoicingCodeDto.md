
# InvoicingCodeDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** |  |  [optional]
**dateCode** | **kotlin.Long** |  |  [optional]
**logicalId** | **kotlin.String** |  |  [optional]
**label** | **kotlin.String** |  |  [optional]
**userId** | **kotlin.String** |  |  [optional]
**contactId** | **kotlin.String** |  |  [optional]
**serviceId** | **kotlin.String** |  |  [optional]
**tarificationId** | **kotlin.String** |  |  [optional]
**code** | **kotlin.String** |  |  [optional]
**paymentType** | [**inline**](#PaymentTypeEnum) |  |  [optional]
**paid** | **kotlin.Double** |  |  [optional]
**totalAmount** | **kotlin.Double** |  |  [optional]
**reimbursement** | **kotlin.Double** |  |  [optional]
**patientIntervention** | **kotlin.Double** |  |  [optional]
**doctorSupplement** | **kotlin.Double** |  |  [optional]
**conventionAmount** | **kotlin.Double** |  |  [optional]
**vat** | **kotlin.Double** |  |  [optional]
**error** | **kotlin.String** |  |  [optional]
**&#x60;contract&#x60;** | **kotlin.String** |  |  [optional]
**contractDate** | **kotlin.Long** |  |  [optional]
**units** | **kotlin.Int** |  |  [optional]
**side** | **kotlin.Int** |  |  [optional]
**timeOfDay** | **kotlin.Int** |  |  [optional]
**eidReadingHour** | **kotlin.Int** |  |  [optional]
**eidReadingValue** | **kotlin.String** |  |  [optional]
**override3rdPayerCode** | **kotlin.Int** |  |  [optional]
**override3rdPayerReason** | **kotlin.String** |  |  [optional]
**transplantationCode** | **kotlin.Int** |  |  [optional]
**prescriberNorm** | **kotlin.Int** |  |  [optional]
**percentNorm** | **kotlin.Int** |  |  [optional]
**prescriberNihii** | **kotlin.String** |  |  [optional]
**relatedCode** | **kotlin.String** |  |  [optional]
**prescriptionDate** | **kotlin.Long** |  |  [optional]
**derogationMaxNumber** | **kotlin.Int** |  |  [optional]
**prescriberSsin** | **kotlin.String** |  |  [optional]
**prescriberLastName** | **kotlin.String** |  |  [optional]
**prescriberFirstName** | **kotlin.String** |  |  [optional]
**prescriberCdHcParty** | **kotlin.String** |  |  [optional]
**locationNihii** | **kotlin.String** |  |  [optional]
**locationCdHcParty** | **kotlin.String** |  |  [optional]
**locationService** | **kotlin.Int** |  |  [optional]
**canceled** | **kotlin.Boolean** |  |  [optional]
**accepted** | **kotlin.Boolean** |  |  [optional]
**pending** | **kotlin.Boolean** |  |  [optional]
**resent** | **kotlin.Boolean** |  |  [optional]
**archived** | **kotlin.Boolean** |  |  [optional]
**lost** | **kotlin.Boolean** |  |  [optional]
**insuranceJustification** | **kotlin.Int** |  |  [optional]
**cancelPatientInterventionReason** | **kotlin.Int** |  |  [optional]
**status** | **kotlin.Long** |  |  [optional]
**encryptedSelf** | **kotlin.String** | The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. |  [optional]


<a name="PaymentTypeEnum"></a>
## Enum: paymentType
Name | Value
---- | -----
paymentType | cash, wired, insurance, creditcard, debitcard, paypal, bitcoin, other



