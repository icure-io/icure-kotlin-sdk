
# ServiceDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** | The Id of the Service. We encourage using either a v4 UUID or a HL7 Id. | 
**identifier** | [**kotlin.collections.List&lt;IdentifierDto&gt;**](IdentifierDto.md) |  | 
**cryptedForeignKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | The public patient key, encrypted here for separate Crypto Actors. | 
**delegations** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | The delegations giving access to connected healthcare information. | 
**encryptionKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | The contact secret encryption key used to encrypt the secured properties (like services for example), encrypted for separate Crypto Actors. | 
**content** | [**kotlin.collections.Map&lt;kotlin.String, ContentDto&gt;**](ContentDto.md) | Information contained in the service. Content is localized, using ISO language code as key | 
**textIndexes** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** |  | 
**invoicingCodes** | **kotlin.collections.Set&lt;kotlin.String&gt;** | List of invoicing codes | 
**notes** | [**kotlin.collections.List&lt;AnnotationDto&gt;**](AnnotationDto.md) | Comments - Notes recorded by a HCP about this service | 
**qualifiedLinks** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;&gt;** | Links towards related services (possibly in other contacts) | 
**codes** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes | 
**tags** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. | 
**transactionId** | **kotlin.String** | The transactionId is used when a single service had to be split into parts for technical reasons. Several services with the same non null transaction id form one single service |  [optional]
**contactId** | **kotlin.String** | Id of the contact during which the service is provided |  [optional]
**subContactIds** | **kotlin.collections.Set&lt;kotlin.String&gt;** | List of IDs of all sub-contacts that link the service to structural elements. Only used when the Service is emitted outside of its contact |  [optional]
**plansOfActionIds** | **kotlin.collections.Set&lt;kotlin.String&gt;** | List of IDs of all plans of actions (healthcare approaches) as a part of which the Service is provided. Only used when the Service is emitted outside of its contact |  [optional]
**healthElementsIds** | **kotlin.collections.Set&lt;kotlin.String&gt;** | List of IDs of all healthcare elements for which the service is provided. Only used when the Service is emitted outside of its contact |  [optional]
**formIds** | **kotlin.collections.Set&lt;kotlin.String&gt;** | List of Ids of all forms linked to the Service. Only used when the Service is emitted outside of its contact. |  [optional]
**secretForeignKeys** | **kotlin.collections.Set&lt;kotlin.String&gt;** | The secret patient key, encrypted in the patient document, in clear here. |  [optional]
**label** | **kotlin.String** | Description / Unambiguous qualification (LOINC code) of the type of information contained in the service. Could be a code to qualify temperature, complaint, diagnostic, ... |  [optional]
**index** | **kotlin.Long** | Used for sorting services inside an upper object (A contact, a transaction, a FHIR bundle, ...) |  [optional]
**encryptedContent** | **kotlin.String** |  |  [optional]
**valueDate** | **kotlin.Long** | The date (YYYYMMDDhhmmss) when the Service is noted to have started and also closes on the same date |  [optional]
**openingDate** | **kotlin.Long** | The date (YYYYMMDDhhmmss) of the start of the Service |  [optional]
**closingDate** | **kotlin.Long** | The date (YYYYMMDDhhmmss) marking the end of the Service |  [optional]
**formId** | **kotlin.String** | Id of the form used during the Service |  [optional]
**created** | **kotlin.Long** | The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**modified** | **kotlin.Long** | The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**endOfLife** | **kotlin.Long** | Soft delete (unix epoch in ms) timestamp of the object. |  [optional]
**author** | **kotlin.String** | The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**responsible** | **kotlin.String** | The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**medicalLocationId** | **kotlin.String** | The id of the medical location where this entity was created. |  [optional]
**comment** | **kotlin.String** | Text, comments on the Service provided |  [optional]
**status** | **kotlin.Int** |  |  [optional]
**encryptedSelf** | **kotlin.String** | The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. |  [optional]



