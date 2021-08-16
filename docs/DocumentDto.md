
# DocumentDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** | The Id of the document. We encourage using either a v4 UUID or a HL7 Id. | 
**tags** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. | 
**codes** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes | 
**otherUtis** | **kotlin.collections.Set&lt;kotlin.String&gt;** | Extra Uniform Type Identifiers | 
**secretForeignKeys** | **kotlin.collections.Set&lt;kotlin.String&gt;** | The secretForeignKeys are filled at the to many end of a one to many relationship (for example inside Contact for the Patient -&gt; Contacts relationship). Used when we want to find all contacts for a specific patient. These keys are in clear. You can have several to partition the medical document space. | 
**cryptedForeignKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | The secretForeignKeys are filled at the to many end of a one to many relationship (for example inside Contact for the Patient -&gt; Contacts relationship). Used when we want to find the patient for a specific contact. These keys are the encrypted id (using the hcParty key for the delegate) that can be found in clear inside the patient. ids encrypted using the hcParty keys. | 
**delegations** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | When a document is created, the responsible generates a cryptographically random master key (never to be used for something else than referencing from other entities). He/she encrypts it using his own AES exchange key and stores it as a delegation. The responsible is thus always in the delegations as well | 
**encryptionKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | When a document needs to be encrypted, the responsible generates a cryptographically random master key (different from the delegation key, never to appear in clear anywhere in the db. He/she encrypts it using his own AES exchange key and stores it as a delegation | 
**rev** | **kotlin.String** | The revision of the document in the database, used for conflict management / optimistic locking. |  [optional]
**created** | **kotlin.Long** | The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**modified** | **kotlin.Long** | The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**author** | **kotlin.String** | The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**responsible** | **kotlin.String** | The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**medicalLocationId** | **kotlin.String** | The id of the medical location where this entity was created. |  [optional]
**endOfLife** | **kotlin.Long** | Soft delete (unix epoch in ms) timestamp of the object. |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**objectStoreReference** | **kotlin.String** | Reference in object store |  [optional]
**documentLocation** | [**inline**](#DocumentLocationEnum) | Location of the document |  [optional]
**documentType** | [**inline**](#DocumentTypeEnum) | The type of document, ex: admission, clinical path, document report,invoice, etc. |  [optional]
**documentStatus** | [**inline**](#DocumentStatusEnum) | The status of the development of the document. Ex: Draft, finalized, reviewed, signed, etc. |  [optional]
**externalUri** | **kotlin.String** | When the document is stored in an external repository, this is the uri of the document in that repository |  [optional]
**mainUti** | **kotlin.String** | The main Uniform Type Identifier of the document (https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/understanding_utis/understand_utis_conc/understand_utis_conc.html#//apple_ref/doc/uid/TP40001319-CH202-CHDHIJDE) |  [optional]
**name** | **kotlin.String** | Name of the document |  [optional]
**version** | **kotlin.String** | The document version |  [optional]
**storedICureDocumentId** | **kotlin.String** | The ICureDocument (Form, Contact, ...) that has been used to generate the document |  [optional]
**externalUuid** | **kotlin.String** | A unique external id (from another external source). |  [optional]
**propertySize** | **kotlin.Long** | Size of the document file |  [optional]
**hash** | **kotlin.String** | Hashed version of the document |  [optional]
**openingContactId** | **kotlin.String** | Id of the contact during which the document was created |  [optional]
**attachmentId** | **kotlin.String** | Id of attachment to this document |  [optional]
**encryptedAttachment** | **kotlin.collections.List&lt;kotlin.ByteArray&gt;** |  |  [optional]
**decryptedAttachment** | **kotlin.collections.List&lt;kotlin.ByteArray&gt;** |  |  [optional]
**encryptedSelf** | **kotlin.String** | The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. |  [optional]


<a name="DocumentLocationEnum"></a>
## Enum: documentLocation
Name | Value
---- | -----
documentLocation | annex, body


<a name="DocumentTypeEnum"></a>
## Enum: documentType
Name | Value
---- | -----
documentType | admission, alert, bvt_sample, clinicalpath, clinicalsummary, contactreport, quote, invoice, death, discharge, dischargereport, ebirth_baby_medicalform, ebirth_baby_notification, ebirth_mother_medicalform, ebirth_mother_notification, ecare_safe_consultation, epidemiology, intervention, labrequest, labresult, medicaladvisoragreement, medicationschemeelement, note, notification, pharmaceuticalprescription, prescription, productdelivery, quickdischargereport, radiationexposuremonitoring, referral, report, request, result, sumehr, telemonitoring, template, template_admin, treatmentsuspension, vaccination


<a name="DocumentStatusEnum"></a>
## Enum: documentStatus
Name | Value
---- | -----
documentStatus | draft, finalized, pending_review, reviewed, pending_signature, signed, canceled, sent, delivered



