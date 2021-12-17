
# DocumentTemplateDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** |  | 
**tags** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. | 
**codes** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes | 
**otherUtis** | **kotlin.collections.Set&lt;kotlin.String&gt;** |  | 
**rev** | **kotlin.String** |  |  [optional]
**created** | **kotlin.Long** | The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**modified** | **kotlin.Long** | The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**author** | **kotlin.String** | The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**responsible** | **kotlin.String** | The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**medicalLocationId** | **kotlin.String** | The id of the medical location where this entity was created. |  [optional]
**endOfLife** | **kotlin.Long** | Soft delete (unix epoch in ms) timestamp of the object. |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**attachment** | [**io.icure.kraken.client.infrastructure.ByteArrayWrapper**](io.icure.kraken.client.infrastructure.ByteArrayWrapper.md) |  |  [optional]
**documentType** | [**inline**](#DocumentTypeEnum) | The type of document, ex: admission, clinical path, document report,invoice, etc. |  [optional]
**mainUti** | **kotlin.String** |  |  [optional]
**name** | **kotlin.String** |  |  [optional]
**attachmentId** | **kotlin.String** |  |  [optional]
**version** | [**inline**](#VersionEnum) |  |  [optional]
**owner** | **kotlin.String** |  |  [optional]
**guid** | **kotlin.String** |  |  [optional]
**group** | [**DocumentGroupDto**](DocumentGroupDto.md) |  |  [optional]
**descr** | **kotlin.String** |  |  [optional]
**disabled** | **kotlin.String** |  |  [optional]
**specialty** | [**CodeStubDto**](CodeStubDto.md) |  |  [optional]


<a name="DocumentTypeEnum"></a>
## Enum: documentType
Name | Value
---- | -----
documentType | admission, alert, bvt_sample, clinicalpath, clinicalsummary, contactreport, quote, invoice, death, discharge, dischargereport, ebirth_baby_medicalform, ebirth_baby_notification, ebirth_mother_medicalform, ebirth_mother_notification, ecare_safe_consultation, epidemiology, intervention, labrequest, labresult, medicaladvisoragreement, medicationschemeelement, note, notification, pharmaceuticalprescription, prescription, productdelivery, quickdischargereport, radiationexposuremonitoring, referral, report, request, result, sumehr, telemonitoring, template, template_admin, treatmentsuspension, vaccination


<a name="VersionEnum"></a>
## Enum: version
Name | Value
---- | -----
version | V1_0_0



