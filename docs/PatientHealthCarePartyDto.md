
# PatientHealthCarePartyDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sendFormats** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** | Preferred format of exchange for diverse means of communication | 
**referralPeriods** | [**kotlin.collections.Set&lt;ReferralPeriodDto&gt;**](ReferralPeriodDto.md) | Time periods | 
**referral** | **kotlin.Boolean** |  | 
**type** | [**inline**](#TypeEnum) | Type of care/relationship. |  [optional]
**healthcarePartyId** | **kotlin.String** | UUID of the hcp. |  [optional]
**encryptedSelf** | **kotlin.String** | The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. |  [optional]


<a name="TypeEnum"></a>
## Enum: type
Name | Value
---- | -----
type | doctor, referral, medicalhouse, retirementhome, hospital, other, referringphysician, managingOrganization



