
# AnnotationDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** | The Id of the Annotation. We encourage using either a v4 UUID or a HL7 Id. | 
**author** | **kotlin.String** |  |  [optional]
**created** | **kotlin.Long** | The timestamp (unix epoch in ms) of creation of this note, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**modified** | **kotlin.Long** | The timestamp (unix epoch in ms) of the latest modification of this note, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**text** | **kotlin.String** | Text contained in the note, written as markdown. |  [optional]
**location** | **kotlin.String** | Defines to which part of the corresponding information the note is related to. |  [optional]



