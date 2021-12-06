
# TelecomDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**telecomType** | [**inline**](#TelecomTypeEnum) | The type of telecom method being used, ex: landline phone, mobile phone, email, fax, etc. |  [optional]
**telecomNumber** | **kotlin.String** |  |  [optional]
**telecomDescription** | **kotlin.String** |  |  [optional]
**encryptedSelf** | **kotlin.String** | The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. |  [optional]


<a name="TelecomTypeEnum"></a>
## Enum: telecomType
Name | Value
---- | -----
telecomType | mobile, phone, email, fax, skype, im, medibridge, ehealthbox, apicrypt, web, print, disk, other, pager



