
# ContentDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**stringValue** | **kotlin.String** |  |  [optional]
**numberValue** | **kotlin.Double** |  |  [optional]
**booleanValue** | **kotlin.Boolean** |  |  [optional]
**instantValue** | [**java.time.OffsetDateTime**](java.time.OffsetDateTime.md) |  |  [optional]
**fuzzyDateValue** | **kotlin.Long** | Known values in a date. The format could have a all three (day, month and year) or values on any of these three, whatever is known. |  [optional]
**binaryValue** | **kotlin.ByteArray** |  |  [optional]
**documentId** | **kotlin.String** | Id of the document in which the content is being filled. |  [optional]
**measureValue** | [**MeasureDto**](MeasureDto.md) |  |  [optional]
**medicationValue** | [**MedicationDto**](MedicationDto.md) |  |  [optional]
**compoundValue** | [**kotlin.collections.List&lt;ServiceDto&gt;**](ServiceDto.md) | The service for which the content is being filled |  [optional]



