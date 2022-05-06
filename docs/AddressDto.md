
# AddressDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**telecoms** | [**kotlin.collections.List&lt;TelecomDto&gt;**](TelecomDto.md) | List of other contact details available through telecom services, ex: email, phone number, fax, etc. | 
**addressType** | [**inline**](#AddressTypeEnum) | The type of place the address represents, ex: home, office, hospital, clinic, etc.  |  [optional]
**descr** | **kotlin.String** | Descriptive notes about the address |  [optional]
**street** | **kotlin.String** | Street name |  [optional]
**houseNumber** | **kotlin.String** | Building / house number |  [optional]
**postboxNumber** | **kotlin.String** | Post / PO box number |  [optional]
**postalCode** | **kotlin.String** | Postal/PIN/ZIP/Area code |  [optional]
**city** | **kotlin.String** | Name of city in the address |  [optional]
**state** | **kotlin.String** | Name of state in the Address |  [optional]
**country** | **kotlin.String** | Name / code of country in the address |  [optional]
**note** | **kotlin.String** | Additional notes |  [optional]
**encryptedSelf** | **kotlin.String** | The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. |  [optional]


<a name="AddressTypeEnum"></a>
## Enum: addressType
Name | Value
---- | -----
addressType | home, work, vacation, hospital, clinic, hq, other, temporary, postal, diplomatic, reference, careaddress



