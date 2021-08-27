
# FormTemplateDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** |  | 
**reports** | **kotlin.collections.Set&lt;kotlin.String&gt;** |  | 
**tags** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) |  | 
**rev** | **kotlin.String** |  |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**layout** | [**FormLayout**](FormLayout.md) |  |  [optional]
**templateLayout** | [**FormTemplateLayout**](FormTemplateLayout.md) |  |  [optional]
**name** | **kotlin.String** |  |  [optional]
**guid** | **kotlin.String** |  |  [optional]
**group** | [**DocumentGroupDto**](DocumentGroupDto.md) |  |  [optional]
**descr** | **kotlin.String** |  |  [optional]
**disabled** | **kotlin.String** |  |  [optional]
**specialty** | [**CodeStubDto**](CodeStubDto.md) |  |  [optional]
**author** | **kotlin.String** |  |  [optional]
**formInstancePreferredLocation** | **kotlin.String** |  |  [optional]
**keyboardShortcut** | **kotlin.String** |  |  [optional]
**shortReport** | **kotlin.String** |  |  [optional]
**mediumReport** | **kotlin.String** |  |  [optional]
**longReport** | **kotlin.String** |  |  [optional]
**layoutAttachmentId** | **kotlin.String** |  |  [optional]



