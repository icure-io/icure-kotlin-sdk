
# PatientDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** | the Id of the patient. We encourage using either a v4 UUID or a HL7 Id. | 
**identifier** | [**kotlin.collections.List&lt;IdentifierDto&gt;**](IdentifierDto.md) |  | 
**tags** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. | 
**codes** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes | 
**languages** | **kotlin.collections.List&lt;kotlin.String&gt;** | the list of languages spoken by the patient ordered by fluency (alpha-2 code http://www.loc.gov/standards/iso639-2/ascii_8bits.html). | 
**addresses** | [**kotlin.collections.List&lt;AddressDto&gt;**](AddressDto.md) | the list of addresses (with address type). | 
**mergedIds** | **kotlin.collections.Set&lt;kotlin.String&gt;** | The ids of the patients that have been merged inside this patient. | 
**active** | **kotlin.Boolean** | Is the patient active (boolean). | 
**deactivationReason** | [**inline**](#DeactivationReasonEnum) | When not active, the reason for deactivation. | 
**insurabilities** | [**kotlin.collections.List&lt;InsurabilityDto&gt;**](InsurabilityDto.md) | List of insurance coverages (of class Insurability, see below). | 
**partnerships** | [**kotlin.collections.List&lt;PartnershipDto&gt;**](PartnershipDto.md) | List of partners, or persons of contact (of class Partnership, see below). | 
**patientHealthCareParties** | [**kotlin.collections.List&lt;PatientHealthCarePartyDto&gt;**](PatientHealthCarePartyDto.md) | Links (usually for therapeutic reasons) between this patient and healthcare parties (of class PatientHealthcareParty). | 
**financialInstitutionInformation** | [**kotlin.collections.List&lt;FinancialInstitutionInformationDto&gt;**](FinancialInstitutionInformationDto.md) | Financial information (Bank, bank account) used to reimburse the patient. | 
**medicalHouseContracts** | [**kotlin.collections.List&lt;MedicalHouseContractDto&gt;**](MedicalHouseContractDto.md) | Contracts between the patient and the healthcare entity. | 
**patientProfessions** | [**kotlin.collections.List&lt;CodeStubDto&gt;**](CodeStubDto.md) | Codified list of professions exercised by this patient. | 
**parameters** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;kotlin.String&gt;&gt;** | Extra parameters | 
**properties** | [**kotlin.collections.Set&lt;PropertyStubDto&gt;**](PropertyStubDto.md) | Extra properties | 
**hcPartyKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;kotlin.String&gt;&gt;** | For each couple of HcParties (delegator and delegate), this map contains the exchange AES key. The delegator is always this hcp, the key of the map is the id of the delegate. The AES exchange key is encrypted using RSA twice : once using this hcp public key (index 0 in the Array) and once using the other hcp public key (index 1 in the Array). For a pair of HcParties. Each HcParty always has one AES exchange key for himself. | 
**privateKeyShamirPartitions** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** | The privateKeyShamirPartitions are used to share this hcp&#39;s private RSA key with a series of other hcParties using Shamir&#39;s algorithm. The key of the map is the hcp Id with whom this partition has been shared. The value is \&quot;threshold⎮partition in hex\&quot; encrypted using the the partition&#39;s holder&#39;s public RSA key | 
**secretForeignKeys** | **kotlin.collections.Set&lt;kotlin.String&gt;** | The secretForeignKeys are filled at the to many end of a one to many relationship (for example inside Contact for the Patient -&gt; Contacts relationship). Used when we want to find all contacts for a specific patient. These keys are in clear. You can have several to partition the medical document space. | 
**cryptedForeignKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | The secretForeignKeys are filled at the to many end of a one to many relationship (for example inside Contact for the Patient -&gt; Contacts relationship). Used when we want to find the patient for a specific contact. These keys are the encrypted id (using the hcParty key for the delegate) that can be found in clear inside the patient. ids encrypted using the hcParty keys. | 
**delegations** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | When a document is created, the responsible generates a cryptographically random master key (never to be used for something else than referencing from other entities). He/she encrypts it using his own AES exchange key and stores it as a delegation. The responsible is thus always in the delegations as well | 
**encryptionKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | When a document needs to be encrypted, the responsible generates a cryptographically random master key (different from the delegation key, never to appear in clear anywhere in the db. He/she encrypts it using his own AES exchange key and stores it as a delegation | 
**nonDuplicateIds** | **kotlin.collections.Set&lt;kotlin.String&gt;** |  | 
**encryptedAdministrativesDocuments** | **kotlin.collections.Set&lt;kotlin.String&gt;** |  | 
**schoolingInfos** | [**kotlin.collections.List&lt;SchoolingInfoDto&gt;**](SchoolingInfoDto.md) |  | 
**employementInfos** | [**kotlin.collections.List&lt;EmploymentInfoDto&gt;**](EmploymentInfoDto.md) |  | 
**rev** | **kotlin.String** | the revision of the patient in the database, used for conflict management / optimistic locking. |  [optional]
**created** | **kotlin.Long** | The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**modified** | **kotlin.Long** | The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**author** | **kotlin.String** | The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**responsible** | **kotlin.String** | The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**endOfLife** | **kotlin.Long** | Soft delete (unix epoch in ms) timestamp of the object. |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**firstName** | **kotlin.String** | the firstname (name) of the patient. |  [optional]
**lastName** | **kotlin.String** | the lastname (surname) of the patient. This is the official lastname that should be used for official administrative purposes. |  [optional]
**companyName** | **kotlin.String** | the name of the company this patient is member of. |  [optional]
**civility** | **kotlin.String** | Mr., Ms., Pr., Dr. ... |  [optional]
**gender** | [**inline**](#GenderEnum) | the gender of the patient: male, female, indeterminate, changed, changedToMale, changedToFemale, unknown |  [optional]
**birthSex** | [**inline**](#BirthSexEnum) | the birth sex of the patient: male, female, indeterminate, unknown |  [optional]
**mergeToPatientId** | **kotlin.String** | The id of the patient this patient has been merged with. |  [optional]
**alias** | **kotlin.String** | An alias of the person, nickname, ... |  [optional]
**ssin** | **kotlin.String** | Social security inscription number. |  [optional]
**maidenName** | **kotlin.String** | Lastname at birth (can be different of the current name), depending on the country, must be used to design the patient . |  [optional]
**spouseName** | **kotlin.String** | Lastname of the spouse for a married woman, depending on the country, can be used to design the patient. |  [optional]
**partnerName** | **kotlin.String** | Lastname of the partner, should not be used to design the patient. |  [optional]
**personalStatus** | [**inline**](#PersonalStatusEnum) | any of &#x60;single&#x60;, &#x60;in_couple&#x60;, &#x60;married&#x60;, &#x60;separated&#x60;, &#x60;divorced&#x60;, &#x60;divorcing&#x60;, &#x60;widowed&#x60;, &#x60;widower&#x60;, &#x60;complicated&#x60;, &#x60;unknown&#x60;, &#x60;contract&#x60;, &#x60;other&#x60;. |  [optional]
**dateOfBirth** | **kotlin.Int** | The birthdate encoded as a fuzzy date on 8 positions (YYYYMMDD) MM and/or DD can be set to 00 if unknown (19740000 is a valid date). |  [optional]
**dateOfDeath** | **kotlin.Int** | The date of death encoded as a fuzzy date on 8 positions (YYYYMMDD) MM and/or DD can be set to 00 if unknown (19740000 is a valid date). |  [optional]
**timestampOfLatestEidReading** | **kotlin.Long** | Timestamp of the latest validation of the eID of the person.. |  [optional]
**placeOfBirth** | **kotlin.String** | The place of birth. |  [optional]
**placeOfDeath** | **kotlin.String** | The place of death. |  [optional]
**deceased** | **kotlin.Boolean** | Is the patient deceased. |  [optional]
**education** | **kotlin.String** | The level of education (college degree, undergraduate, phd). |  [optional]
**profession** | **kotlin.String** | The current professional activity. |  [optional]
**note** | **kotlin.String** | A text note (can be confidential, encrypted by default). |  [optional]
**administrativeNote** | **kotlin.String** | An administrative note, not confidential. |  [optional]
**nationality** | **kotlin.String** | The nationality of the patient. |  [optional]
**race** | **kotlin.String** | The race of the patient. |  [optional]
**ethnicity** | **kotlin.String** | The ethnicity of the patient. |  [optional]
**preferredUserId** | **kotlin.String** | The id of the user that usually handles this patient. |  [optional]
**picture** | **kotlin.collections.List&lt;kotlin.ByteArray&gt;** | A picture usually saved in JPEG format. |  [optional]
**externalId** | **kotlin.String** | An external (from another source) id with no guarantee or requirement for unicity . |  [optional]
**publicKey** | **kotlin.String** | The public key of this hcp |  [optional]
**encryptedSelf** | **kotlin.String** | The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. |  [optional]
**medicalLocationId** | **kotlin.String** | The id of the medical location where this entity was created. |  [optional]
**comment** | **kotlin.String** |  |  [optional]
**warning** | **kotlin.String** |  |  [optional]
**fatherBirthCountry** | [**CodeStubDto**](CodeStubDto.md) |  |  [optional]
**birthCountry** | [**CodeStubDto**](CodeStubDto.md) |  |  [optional]
**nativeCountry** | [**CodeStubDto**](CodeStubDto.md) |  |  [optional]
**socialStatus** | [**CodeStubDto**](CodeStubDto.md) |  |  [optional]
**mainSourceOfIncome** | [**CodeStubDto**](CodeStubDto.md) |  |  [optional]


<a name="DeactivationReasonEnum"></a>
## Enum: deactivationReason
Name | Value
---- | -----
deactivationReason | deceased, moved, other_doctor, retired, no_contact, unknown, none


<a name="GenderEnum"></a>
## Enum: gender
Name | Value
---- | -----
gender | male, female, indeterminate, changed, changedToMale, changedToFemale, unknown


<a name="BirthSexEnum"></a>
## Enum: birthSex
Name | Value
---- | -----
birthSex | male, female, indeterminate, changed, changedToMale, changedToFemale, unknown


<a name="PersonalStatusEnum"></a>
## Enum: personalStatus
Name | Value
---- | -----
personalStatus | single, in_couple, married, separated, divorced, divorcing, widowed, widower, complicated, unknown, contract, other



