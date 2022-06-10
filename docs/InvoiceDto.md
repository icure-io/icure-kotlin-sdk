
# InvoiceDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** | The Id of the Invoice. We encourage using either a v4 UUID or a HL7 Id. | 
**tags** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. | 
**codes** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes | 
**invoicingCodes** | [**kotlin.collections.List&lt;InvoicingCodeDto&gt;**](InvoicingCodeDto.md) |  | 
**receipts** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** |  | 
**options** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** |  | 
**secretForeignKeys** | **kotlin.collections.Set&lt;kotlin.String&gt;** | The secretForeignKeys are filled at the to many end of a one to many relationship (for example inside Contact for the Patient -&gt; Contacts relationship). Used when we want to find all contacts for a specific patient. These keys are in clear. You can have several to partition the medical document space. | 
**cryptedForeignKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | The secretForeignKeys are filled at the to many end of a one to many relationship (for example inside Contact for the Patient -&gt; Contacts relationship). Used when we want to find the patient for a specific contact. These keys are the encrypted id (using the hcParty key for the delegate) that can be found in clear inside the patient. ids encrypted using the hcParty keys. | 
**delegations** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | When a document is created, the responsible generates a cryptographically random master key (never to be used for something else than referencing from other entities). He/she encrypts it using his own AES exchange key and stores it as a delegation. The responsible is thus always in the delegations as well | 
**encryptionKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;DelegationDto&gt;&gt;** | When a document needs to be encrypted, the responsible generates a cryptographically random master key (different from the delegation key, never to appear in clear anywhere in the db. He/she encrypts it using his own AES exchange key and stores it as a delegation | 
**rev** | **kotlin.String** | The revision of the invoice in the database, used for conflict management / optimistic locking. |  [optional]
**created** | **kotlin.Long** | The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**modified** | **kotlin.Long** | The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**author** | **kotlin.String** | The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**responsible** | **kotlin.String** | The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**medicalLocationId** | **kotlin.String** | The id of the medical location where this entity was created. |  [optional]
**endOfLife** | **kotlin.Long** | Soft delete (unix epoch in ms) timestamp of the object. |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**invoiceDate** | **kotlin.Long** | The timestamp (unix epoch in ms) when the invoice was drafted, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**sentDate** | **kotlin.Long** | The timestamp (unix epoch in ms) when the invoice was sent, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**printedDate** | **kotlin.Long** | The timestamp (unix epoch in ms) when the invoice is printed, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**recipientType** | **kotlin.String** | The type of user that receives the invoice, a patient or a healthcare party |  [optional]
**recipientId** | **kotlin.String** | Id of the recipient of the invoice. For healthcare party and insurance, patient link happens through secretForeignKeys |  [optional]
**invoiceReference** | **kotlin.String** |  |  [optional]
**thirdPartyReference** | **kotlin.String** |  |  [optional]
**thirdPartyPaymentJustification** | **kotlin.String** |  |  [optional]
**thirdPartyPaymentReason** | **kotlin.String** |  |  [optional]
**reason** | **kotlin.String** |  |  [optional]
**invoiceType** | [**inline**](#InvoiceTypeEnum) | The format the invoice should follow based on the recipient which could be a patient, mutual fund or paying agency such as the CPAS |  [optional]
**sentMediumType** | [**inline**](#SentMediumTypeEnum) | Medium of the invoice: CD ROM, Email, paper, etc. |  [optional]
**interventionType** | [**inline**](#InterventionTypeEnum) |  |  [optional]
**groupId** | **kotlin.String** |  |  [optional]
**paymentType** | [**inline**](#PaymentTypeEnum) | Type of payment, ex: cash, wired, insurance, debit card, etc. |  [optional]
**paid** | **kotlin.Double** |  |  [optional]
**payments** | [**kotlin.collections.List&lt;PaymentDto&gt;**](PaymentDto.md) |  |  [optional]
**gnotionNihii** | **kotlin.String** |  |  [optional]
**gnotionSsin** | **kotlin.String** |  |  [optional]
**gnotionLastName** | **kotlin.String** |  |  [optional]
**gnotionFirstName** | **kotlin.String** |  |  [optional]
**gnotionCdHcParty** | **kotlin.String** |  |  [optional]
**invoicePeriod** | **kotlin.Int** |  |  [optional]
**careProviderType** | **kotlin.String** |  |  [optional]
**internshipNihii** | **kotlin.String** |  |  [optional]
**internshipSsin** | **kotlin.String** |  |  [optional]
**internshipLastName** | **kotlin.String** |  |  [optional]
**internshipFirstName** | **kotlin.String** |  |  [optional]
**internshipCdHcParty** | **kotlin.String** |  |  [optional]
**internshipCbe** | **kotlin.String** |  |  [optional]
**supervisorNihii** | **kotlin.String** |  |  [optional]
**supervisorSsin** | **kotlin.String** |  |  [optional]
**supervisorLastName** | **kotlin.String** |  |  [optional]
**supervisorFirstName** | **kotlin.String** |  |  [optional]
**supervisorCdHcParty** | **kotlin.String** |  |  [optional]
**supervisorCbe** | **kotlin.String** |  |  [optional]
**error** | **kotlin.String** |  |  [optional]
**encounterLocationName** | **kotlin.String** |  |  [optional]
**encounterLocationNihii** | **kotlin.String** |  |  [optional]
**encounterLocationNorm** | **kotlin.Int** |  |  [optional]
**longDelayJustification** | **kotlin.Int** |  |  [optional]
**correctiveInvoiceId** | **kotlin.String** |  |  [optional]
**correctedInvoiceId** | **kotlin.String** |  |  [optional]
**creditNote** | **kotlin.Boolean** |  |  [optional]
**creditNoteRelatedInvoiceId** | **kotlin.String** |  |  [optional]
**idDocument** | [**IdentityDocumentReaderDto**](IdentityDocumentReaderDto.md) |  |  [optional]
**admissionDate** | **kotlin.Long** |  |  [optional]
**locationNihii** | **kotlin.String** |  |  [optional]
**locationService** | **kotlin.Int** |  |  [optional]
**cancelReason** | **kotlin.String** |  |  [optional]
**cancelDate** | **kotlin.Long** |  |  [optional]
**encryptedSelf** | **kotlin.String** | The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. |  [optional]


<a name="InvoiceTypeEnum"></a>
## Enum: invoiceType
Name | Value
---- | -----
invoiceType | patient, mutualfund, payingagency, insurance, efact, other


<a name="SentMediumTypeEnum"></a>
## Enum: sentMediumType
Name | Value
---- | -----
sentMediumType | cdrom, eattest, efact, email, mediprima, paper, stat


<a name="InterventionTypeEnum"></a>
## Enum: interventionType
Name | Value
---- | -----
interventionType | total, userfees


<a name="PaymentTypeEnum"></a>
## Enum: paymentType
Name | Value
---- | -----
paymentType | cash, wired, insurance, creditcard, debitcard, paypal, bitcoin, other



