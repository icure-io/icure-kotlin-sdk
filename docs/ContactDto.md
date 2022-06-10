
# ContactDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** | the Id of the contact. We encourage using either a v4 UUID or a HL7 Id. | 
**tags** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. | 
**codes** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes | 
**identifier** | [**kotlin.collections.List&lt;IdentifierDto&gt;**](IdentifierDto.md) | The identifiers of the Contact | 
**subContacts** | [**kotlin.collections.Set&lt;SubContactDto&gt;**](SubContactDto.md) | Set of all sub-contacts recorded during the given contact. Sub-contacts are used to link services embedded inside this contact to healthcare elements, healthcare approaches and/or forms. | 
**services** | [**kotlin.collections.Set&lt;ServiceDto&gt;**](ServiceDto.md) | Set of all services provided to the patient during the contact. | 
**secretForeignKeys** | **kotlin.collections.Set&lt;kotlin.String&gt;** | The secretForeignKeys are filled at the to many end of a one to many relationship (for example inside Contact for the Patient -&gt; Contacts relationship). Used when we want to find all contacts for a specific patient. These keys are in clear. You can have several to partition the medical document space. | 
**cryptedForeignKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | The secretForeignKeys are filled at the to many end of a one to many relationship (for example inside Contact for the Patient -&gt; Contacts relationship). Used when we want to find the patient for a specific contact. These keys are the encrypted id (using the hcParty key for the delegate) that can be found in clear inside the patient. ids encrypted using the hcParty keys. | 
**delegations** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | When a document is created, the responsible generates a cryptographically random master key (never to be used for something else than referencing from other entities). He/she encrypts it using his own AES exchange key and stores it as a delegation. The responsible is thus always in the delegations as well | 
**encryptionKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | When a document needs to be encrypted, the responsible generates a cryptographically random master key (different from the delegation key, never to appear in clear anywhere in the db. He/she encrypts it using his own AES exchange key and stores it as a delegation | 
**rev** | **kotlin.String** | the revision of the contact in the database, used for conflict management / optimistic locking. |  [optional]
**created** | **kotlin.Long** | The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**modified** | **kotlin.Long** | The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**author** | **kotlin.String** | The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**responsible** | **kotlin.String** | The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**medicalLocationId** | **kotlin.String** | The id of the medical location where this entity was created. |  [optional]
**endOfLife** | **kotlin.Long** | Soft delete (unix epoch in ms) timestamp of the object. |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**groupId** | **kotlin.String** | Separate contacts can merged in one logical contact if they share the same groupId. When a contact must be split to selectively assign rights to healthcare parties, the split contacts all share the same groupId |  [optional]
**openingDate** | **kotlin.Long** | The date (YYYYMMDDhhmmss) of the start of the contact. |  [optional]
**closingDate** | **kotlin.Long** | The date (YYYYMMDDhhmmss) marking the end of the contact. |  [optional]
**descr** | **kotlin.String** | Description of the contact |  [optional]
**location** | **kotlin.String** | Location where the contact was recorded. |  [optional]
**externalId** | **kotlin.String** | An external (from another source) id with no guarantee or requirement for unicity. |  [optional]
**encounterType** | [**CodeStubDto**](CodeStubDto.md) |  |  [optional]
**healthcarePartyId** | **kotlin.String** |  |  [optional]
**modifiedContactId** | **kotlin.String** |  |  [optional]
**encryptedSelf** | **kotlin.String** | The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. |  [optional]



