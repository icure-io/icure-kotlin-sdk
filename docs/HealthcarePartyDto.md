
# HealthcarePartyDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** | the Id of the healthcare party. We encourage using either a v4 UUID or a HL7 Id. | 
**names** | [**kotlin.collections.List&lt;PersonNameDto&gt;**](PersonNameDto.md) | the list of all names of the healthcare party, also containing the official full name information. Ordered by preference of use. First element is therefore the official name used for the healthcare party in the application | 
**addresses** | [**kotlin.collections.List&lt;AddressDto&gt;**](AddressDto.md) | The list of addresses (with address type). | 
**languages** | **kotlin.collections.List&lt;kotlin.String&gt;** | The list of languages spoken by the patient ordered by fluency (alpha-2 code http://www.loc.gov/standards/iso639-2/ascii_8bits.html). | 
**statuses** | [**inline**](#kotlin.collections.Set&lt;StatusesEnum&gt;) | The healthcare party&#39;s status: &#39;trainee&#39; or &#39;withconvention&#39; or &#39;accredited&#39; | 
**statusHistory** | [**kotlin.collections.List&lt;HealthcarePartyHistoryStatusDto&gt;**](HealthcarePartyHistoryStatusDto.md) | The healthcare party&#39;s status history | 
**specialityCodes** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | Medical specialty of the healthcare party codified using FHIR or Kmehr codificaiton scheme | 
**sendFormats** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** | The type of format for contacting the healthcare party, ex: mobile, phone, email, etc. | 
**financialInstitutionInformation** | [**kotlin.collections.List&lt;FinancialInstitutionInformationDto&gt;**](FinancialInstitutionInformationDto.md) | List of financial information (Bank, bank account). | 
**flatRateTarifications** | [**kotlin.collections.List&lt;FlatRateTarificationDto&gt;**](FlatRateTarificationDto.md) |  | 
**importedData** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** |  | 
**options** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** |  | 
**properties** | [**kotlin.collections.Set&lt;PropertyStubDto&gt;**](PropertyStubDto.md) |  | 
**hcPartyKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;kotlin.String&gt;&gt;** | For each couple of HcParties (delegator and delegate), this map contains the exchange AES key. The delegator is always this hcp, the key of the map is the id of the delegate. The AES exchange key is encrypted using RSA twice : once using this hcp public key (index 0 in the Array) and once using the other hcp public key (index 1 in the Array). For a pair of HcParties. Each HcParty always has one AES exchange key for himself. | 
**aesExchangeKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;kotlin.String&gt;&gt;&gt;** | Extra AES exchange keys, usually the ones we lost access to at some point. The structure is { publicKey: { delegateId: [aesExKey_for_this, aesExKey_for_delegate] } } | 
**transferKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;&gt;** | Our private keys encrypted with our public keys. The structure is { publicKey1: { publicKey2: privateKey2_encrypted_with_publicKey1, publicKey3: privateKey3_encrypted_with_publicKey1 } } | 
**lostHcPartyKeys** | **kotlin.collections.Set&lt;kotlin.String&gt;** | The hcparty keys (first of the pair) for which we are asking a re-encryption by the delegate using our new publicKey. | 
**privateKeyShamirPartitions** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** | The privateKeyShamirPartitions are used to share this hcp&#39;s private RSA key with a series of other hcParties using Shamir&#39;s algorithm. The key of the map is the hcp Id with whom this partition has been shared. The value is \&quot;threshold⎮partition in hex\&quot; encrypted using the the partition&#39;s holder&#39;s public RSA key | 
**rev** | **kotlin.String** | the revision of the healthcare party in the database, used for conflict management / optimistic locking. |  [optional]
**created** | **kotlin.Long** | creation timestamp of the object. |  [optional]
**modified** | **kotlin.Long** | last modification timestamp of the object. |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**name** | **kotlin.String** | The full name of the healthcare party, used mainly when the healthcare party is an organization |  [optional]
**lastName** | **kotlin.String** | the lastname (surname) of the healthcare party. This is the official lastname that should be used for official administrative purposes. |  [optional]
**firstName** | **kotlin.String** | the firstname (name) of the healthcare party. |  [optional]
**gender** | [**inline**](#GenderEnum) | the gender of the healthcare party: male, female, indeterminate, changed, changedToMale, changedToFemale, unknown |  [optional]
**civility** | **kotlin.String** | Mr., Ms., Pr., Dr. ... |  [optional]
**companyName** | **kotlin.String** | The name of the company this healthcare party is member of |  [optional]
**speciality** | **kotlin.String** | Medical specialty of the healthcare party |  [optional]
**bankAccount** | **kotlin.String** | Bank Account identifier of the healhtcare party, IBAN, deprecated, use financial institutions instead |  [optional]
**bic** | **kotlin.String** | Bank Identifier Code, the SWIFT Address assigned to the bank, use financial institutions instead |  [optional]
**proxyBankAccount** | **kotlin.String** |  |  [optional]
**proxyBic** | **kotlin.String** |  |  [optional]
**invoiceHeader** | **kotlin.String** | All details included in the invoice header |  [optional]
**cbe** | **kotlin.String** | Identifier number for institution type if the healthcare party is an enterprise |  [optional]
**ehp** | **kotlin.String** | Identifier number for the institution if the healthcare party is an organization |  [optional]
**userId** | **kotlin.String** | The id of the user that usually handles this healthcare party. |  [optional]
**parentId** | **kotlin.String** | Id of parent of the user representing the healthcare party. |  [optional]
**convention** | **kotlin.Int** |  |  [optional]
**nihii** | **kotlin.String** | National Institute for Health and Invalidity Insurance number assigned to healthcare parties (institution or person). |  [optional]
**nihiiSpecCode** | **kotlin.String** |  |  [optional]
**ssin** | **kotlin.String** | Social security inscription number. |  [optional]
**picture** | [**io.icure.kraken.client.infrastructure.ByteArrayWrapper**](io.icure.kraken.client.infrastructure.ByteArrayWrapper.md) | A picture usually saved in JPEG format. |  [optional]
**notes** | **kotlin.String** | Text notes. |  [optional]
**descr** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** | A description of the HCP, meant for the public and in multiple languages. |  [optional]
**billingType** | **kotlin.String** | The invoicing scheme this healthcare party adheres to : &#39;service fee&#39; or &#39;flat rate&#39; |  [optional]
**type** | **kotlin.String** |  |  [optional]
**contactPerson** | **kotlin.String** |  |  [optional]
**contactPersonHcpId** | **kotlin.String** |  |  [optional]
**supervisorId** | **kotlin.String** |  |  [optional]
**publicKey** | **kotlin.String** | The public key of this hcp |  [optional]


<a name="kotlin.collections.Set<StatusesEnum>"></a>
## Enum: statuses
Name | Value
---- | -----
statuses | trainee, withconvention, accreditated


<a name="GenderEnum"></a>
## Enum: gender
Name | Value
---- | -----
gender | male, female, indeterminate, changed, changedToMale, changedToFemale, unknown



