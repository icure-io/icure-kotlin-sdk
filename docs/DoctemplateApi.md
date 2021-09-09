# DoctemplateApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createDocumentTemplate**](DoctemplateApi.md#createDocumentTemplate) | **POST** /rest/v1/doctemplate | Create a document template with the current user
[**deleteDocumentTemplate**](DoctemplateApi.md#deleteDocumentTemplate) | **DELETE** /rest/v1/doctemplate/{documentTemplateIds} | Deletes a document template
[**findAllDocumentTemplates**](DoctemplateApi.md#findAllDocumentTemplates) | **GET** /rest/v1/doctemplate/find/all | Gets all document templates for all users
[**findDocumentTemplates**](DoctemplateApi.md#findDocumentTemplates) | **GET** /rest/v1/doctemplate | Gets all document templates for current user
[**findDocumentTemplatesByDocumentType**](DoctemplateApi.md#findDocumentTemplatesByDocumentType) | **GET** /rest/v1/doctemplate/byDocumentType/{documentTypeCode} | Gets all document templates by Type
[**findDocumentTemplatesByDocumentTypeForCurrentUser**](DoctemplateApi.md#findDocumentTemplatesByDocumentTypeForCurrentUser) | **GET** /rest/v1/doctemplate/byDocumentTypeForCurrentUser/{documentTypeCode} | Gets all document templates by Type For currentUser
[**findDocumentTemplatesBySpeciality**](DoctemplateApi.md#findDocumentTemplatesBySpeciality) | **GET** /rest/v1/doctemplate/bySpecialty/{specialityCode} | Gets all document templates
[**getAttachmentText**](DoctemplateApi.md#getAttachmentText) | **GET** /rest/v1/doctemplate/{documentTemplateId}/attachmentText/{attachmentId} | Download a the document template attachment
[**getDocumentTemplate**](DoctemplateApi.md#getDocumentTemplate) | **GET** /rest/v1/doctemplate/{documentTemplateId} | Gets a document template
[**getDocumentTemplateAttachment**](DoctemplateApi.md#getDocumentTemplateAttachment) | **GET** /rest/v1/doctemplate/{documentTemplateId}/attachment/{attachmentId} | Download a the document template attachment
[**setDocumentTemplateAttachment**](DoctemplateApi.md#setDocumentTemplateAttachment) | **PUT** /rest/v1/doctemplate/{documentTemplateId}/attachment | Creates a document&#39;s attachment
[**setDocumentTemplateAttachmentJson**](DoctemplateApi.md#setDocumentTemplateAttachmentJson) | **PUT** /rest/v1/doctemplate/{documentTemplateId}/attachmentJson | Creates a document&#39;s attachment
[**updateDocumentTemplate**](DoctemplateApi.md#updateDocumentTemplate) | **PUT** /rest/v1/doctemplate/{documentTemplateId} | Modify a document template with the current user


<a name="createDocumentTemplate"></a>
# **createDocumentTemplate**
> DocumentTemplateDto createDocumentTemplate(documentTemplateDto)

Create a document template with the current user

Returns an instance of created document template.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTemplateDto : DocumentTemplateDto =  // DocumentTemplateDto | 
try {
    val result : DocumentTemplateDto = apiInstance.createDocumentTemplate(documentTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#createDocumentTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#createDocumentTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateDto** | [**DocumentTemplateDto**](DocumentTemplateDto.md)|  |

### Return type

[**DocumentTemplateDto**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteDocumentTemplate"></a>
# **deleteDocumentTemplate**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteDocumentTemplate(documentTemplateIds)

Deletes a document template

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTemplateIds : kotlin.String = documentTemplateIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteDocumentTemplate(documentTemplateIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#deleteDocumentTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#deleteDocumentTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findAllDocumentTemplates"></a>
# **findAllDocumentTemplates**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; findAllDocumentTemplates()

Gets all document templates for all users

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.findAllDocumentTemplates()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#findAllDocumentTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#findAllDocumentTemplates")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;DocumentTemplateDto&gt;**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findDocumentTemplates"></a>
# **findDocumentTemplates**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; findDocumentTemplates()

Gets all document templates for current user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.findDocumentTemplates()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#findDocumentTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#findDocumentTemplates")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;DocumentTemplateDto&gt;**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findDocumentTemplatesByDocumentType"></a>
# **findDocumentTemplatesByDocumentType**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; findDocumentTemplatesByDocumentType(documentTypeCode)

Gets all document templates by Type

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTypeCode : kotlin.String = documentTypeCode_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.findDocumentTemplatesByDocumentType(documentTypeCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#findDocumentTemplatesByDocumentType")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#findDocumentTemplatesByDocumentType")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTypeCode** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocumentTemplateDto&gt;**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findDocumentTemplatesByDocumentTypeForCurrentUser"></a>
# **findDocumentTemplatesByDocumentTypeForCurrentUser**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; findDocumentTemplatesByDocumentTypeForCurrentUser(documentTypeCode)

Gets all document templates by Type For currentUser

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTypeCode : kotlin.String = documentTypeCode_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.findDocumentTemplatesByDocumentTypeForCurrentUser(documentTypeCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#findDocumentTemplatesByDocumentTypeForCurrentUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#findDocumentTemplatesByDocumentTypeForCurrentUser")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTypeCode** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocumentTemplateDto&gt;**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findDocumentTemplatesBySpeciality"></a>
# **findDocumentTemplatesBySpeciality**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; findDocumentTemplatesBySpeciality(specialityCode)

Gets all document templates

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val specialityCode : kotlin.String = specialityCode_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.findDocumentTemplatesBySpeciality(specialityCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#findDocumentTemplatesBySpeciality")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#findDocumentTemplatesBySpeciality")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **specialityCode** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocumentTemplateDto&gt;**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getAttachmentText"></a>
# **getAttachmentText**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; getAttachmentText(documentTemplateId, attachmentId)

Download a the document template attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val attachmentId : kotlin.String = attachmentId_example // kotlin.String | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.getAttachmentText(documentTemplateId, attachmentId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#getAttachmentText")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#getAttachmentText")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateId** | **kotlin.String**|  |
 **attachmentId** | **kotlin.String**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

<a name="getDocumentTemplate"></a>
# **getDocumentTemplate**
> DocumentTemplateDto getDocumentTemplate(documentTemplateId)

Gets a document template

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
try {
    val result : DocumentTemplateDto = apiInstance.getDocumentTemplate(documentTemplateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#getDocumentTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#getDocumentTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateId** | **kotlin.String**|  |

### Return type

[**DocumentTemplateDto**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getDocumentTemplateAttachment"></a>
# **getDocumentTemplateAttachment**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; getDocumentTemplateAttachment(documentTemplateId, attachmentId)

Download a the document template attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val attachmentId : kotlin.String = attachmentId_example // kotlin.String | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.getDocumentTemplateAttachment(documentTemplateId, attachmentId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#getDocumentTemplateAttachment")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#getDocumentTemplateAttachment")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateId** | **kotlin.String**|  |
 **attachmentId** | **kotlin.String**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

<a name="setDocumentTemplateAttachment"></a>
# **setDocumentTemplateAttachment**
> DocumentTemplateDto setDocumentTemplateAttachment(documentTemplateId, body)

Creates a document&#39;s attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
try {
    val result : DocumentTemplateDto = apiInstance.setDocumentTemplateAttachment(documentTemplateId, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#setDocumentTemplateAttachment")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#setDocumentTemplateAttachment")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateId** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |

### Return type

[**DocumentTemplateDto**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

<a name="setDocumentTemplateAttachmentJson"></a>
# **setDocumentTemplateAttachmentJson**
> DocumentTemplateDto setDocumentTemplateAttachmentJson(documentTemplateId, body)

Creates a document&#39;s attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
try {
    val result : DocumentTemplateDto = apiInstance.setDocumentTemplateAttachmentJson(documentTemplateId, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#setDocumentTemplateAttachmentJson")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#setDocumentTemplateAttachmentJson")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateId** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |

### Return type

[**DocumentTemplateDto**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

<a name="updateDocumentTemplate"></a>
# **updateDocumentTemplate**
> DocumentTemplateDto updateDocumentTemplate(documentTemplateId, documentTemplateDto)

Modify a document template with the current user

Returns an instance of created document template.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DoctemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val documentTemplateDto : DocumentTemplateDto =  // DocumentTemplateDto | 
try {
    val result : DocumentTemplateDto = apiInstance.updateDocumentTemplate(documentTemplateId, documentTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DoctemplateApi#updateDocumentTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DoctemplateApi#updateDocumentTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateId** | **kotlin.String**|  |
 **documentTemplateDto** | [**DocumentTemplateDto**](DocumentTemplateDto.md)|  |

### Return type

[**DocumentTemplateDto**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

