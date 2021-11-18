# DocumentTemplateApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createDocumentTemplate**](DocumentTemplateApi.md#createDocumentTemplate) | **POST** /rest/v2/doctemplate | Create a document template with the current user
[**deleteDocumentTemplates**](DocumentTemplateApi.md#deleteDocumentTemplates) | **POST** /rest/v2/doctemplate/delete/batch | Deletes document templates
[**getAttachmentText**](DocumentTemplateApi.md#getAttachmentText) | **GET** /rest/v2/doctemplate/{documentTemplateId}/attachmentText/{attachmentId} | Download a the document template attachment
[**getDocumentTemplate**](DocumentTemplateApi.md#getDocumentTemplate) | **GET** /rest/v2/doctemplate/{documentTemplateId} | Gets a document template
[**getDocumentTemplateAttachment**](DocumentTemplateApi.md#getDocumentTemplateAttachment) | **GET** /rest/v2/doctemplate/{documentTemplateId}/attachment/{attachmentId} | Download a the document template attachment
[**listAllDocumentTemplates**](DocumentTemplateApi.md#listAllDocumentTemplates) | **GET** /rest/v2/doctemplate/find/all | Gets all document templates for all users
[**listDocumentTemplates**](DocumentTemplateApi.md#listDocumentTemplates) | **GET** /rest/v2/doctemplate | Gets all document templates for current user
[**listDocumentTemplatesByDocumentType**](DocumentTemplateApi.md#listDocumentTemplatesByDocumentType) | **GET** /rest/v2/doctemplate/byDocumentType/{documentTypeCode} | Gets all document templates by Type
[**listDocumentTemplatesByDocumentTypeForCurrentUser**](DocumentTemplateApi.md#listDocumentTemplatesByDocumentTypeForCurrentUser) | **GET** /rest/v2/doctemplate/byDocumentTypeForCurrentUser/{documentTypeCode} | Gets all document templates by Type For currentUser
[**listDocumentTemplatesBySpeciality**](DocumentTemplateApi.md#listDocumentTemplatesBySpeciality) | **GET** /rest/v2/doctemplate/bySpecialty/{specialityCode} | Gets all document templates
[**modifyDocumentTemplate**](DocumentTemplateApi.md#modifyDocumentTemplate) | **PUT** /rest/v2/doctemplate/{documentTemplateId} | Modify a document template with the current user
[**setDocumentTemplateAttachment**](DocumentTemplateApi.md#setDocumentTemplateAttachment) | **PUT** /rest/v2/doctemplate/{documentTemplateId}/attachment | Creates a document&#39;s attachment
[**setDocumentTemplateAttachmentJson**](DocumentTemplateApi.md#setDocumentTemplateAttachmentJson) | **PUT** /rest/v2/doctemplate/{documentTemplateId}/attachmentJson | Creates a document&#39;s attachment


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

val apiInstance = DocumentTemplateApi()
val documentTemplateDto : DocumentTemplateDto =  // DocumentTemplateDto | 
try {
    val result : DocumentTemplateDto = apiInstance.createDocumentTemplate(documentTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#createDocumentTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#createDocumentTemplate")
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

<a name="deleteDocumentTemplates"></a>
# **deleteDocumentTemplates**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteDocumentTemplates(listOfIdsDto)

Deletes document templates

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentTemplateApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteDocumentTemplates(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#deleteDocumentTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#deleteDocumentTemplates")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
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

val apiInstance = DocumentTemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val attachmentId : kotlin.String = attachmentId_example // kotlin.String | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.getAttachmentText(documentTemplateId, attachmentId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#getAttachmentText")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#getAttachmentText")
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

val apiInstance = DocumentTemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
try {
    val result : DocumentTemplateDto = apiInstance.getDocumentTemplate(documentTemplateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#getDocumentTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#getDocumentTemplate")
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

val apiInstance = DocumentTemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val attachmentId : kotlin.String = attachmentId_example // kotlin.String | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.getDocumentTemplateAttachment(documentTemplateId, attachmentId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#getDocumentTemplateAttachment")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#getDocumentTemplateAttachment")
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

<a name="listAllDocumentTemplates"></a>
# **listAllDocumentTemplates**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; listAllDocumentTemplates()

Gets all document templates for all users

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentTemplateApi()
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.listAllDocumentTemplates()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#listAllDocumentTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#listAllDocumentTemplates")
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

<a name="listDocumentTemplates"></a>
# **listDocumentTemplates**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; listDocumentTemplates()

Gets all document templates for current user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentTemplateApi()
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.listDocumentTemplates()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#listDocumentTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#listDocumentTemplates")
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

<a name="listDocumentTemplatesByDocumentType"></a>
# **listDocumentTemplatesByDocumentType**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; listDocumentTemplatesByDocumentType(documentTypeCode)

Gets all document templates by Type

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentTemplateApi()
val documentTypeCode : kotlin.String = documentTypeCode_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.listDocumentTemplatesByDocumentType(documentTypeCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#listDocumentTemplatesByDocumentType")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#listDocumentTemplatesByDocumentType")
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

<a name="listDocumentTemplatesByDocumentTypeForCurrentUser"></a>
# **listDocumentTemplatesByDocumentTypeForCurrentUser**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; listDocumentTemplatesByDocumentTypeForCurrentUser(documentTypeCode)

Gets all document templates by Type For currentUser

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentTemplateApi()
val documentTypeCode : kotlin.String = documentTypeCode_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.listDocumentTemplatesByDocumentTypeForCurrentUser(documentTypeCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#listDocumentTemplatesByDocumentTypeForCurrentUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#listDocumentTemplatesByDocumentTypeForCurrentUser")
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

<a name="listDocumentTemplatesBySpeciality"></a>
# **listDocumentTemplatesBySpeciality**
> kotlin.collections.List&lt;DocumentTemplateDto&gt; listDocumentTemplatesBySpeciality(specialityCode)

Gets all document templates

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentTemplateApi()
val specialityCode : kotlin.String = specialityCode_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocumentTemplateDto> = apiInstance.listDocumentTemplatesBySpeciality(specialityCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#listDocumentTemplatesBySpeciality")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#listDocumentTemplatesBySpeciality")
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

<a name="modifyDocumentTemplate"></a>
# **modifyDocumentTemplate**
> DocumentTemplateDto modifyDocumentTemplate(documentTemplateId, documentTemplateDto)

Modify a document template with the current user

Returns an instance of created document template.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentTemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val documentTemplateDto : DocumentTemplateDto =  // DocumentTemplateDto | 
try {
    val result : DocumentTemplateDto = apiInstance.modifyDocumentTemplate(documentTemplateId, documentTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#modifyDocumentTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#modifyDocumentTemplate")
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

<a name="setDocumentTemplateAttachment"></a>
# **setDocumentTemplateAttachment**
> DocumentTemplateDto setDocumentTemplateAttachment(documentTemplateId, ioIcureKrakenClientInfrastructureByteArrayWrapper)

Creates a document&#39;s attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentTemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val ioIcureKrakenClientInfrastructureByteArrayWrapper : kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> =  // kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> | 
try {
    val result : DocumentTemplateDto = apiInstance.setDocumentTemplateAttachment(documentTemplateId, ioIcureKrakenClientInfrastructureByteArrayWrapper)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#setDocumentTemplateAttachment")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#setDocumentTemplateAttachment")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateId** | **kotlin.String**|  |
 **ioIcureKrakenClientInfrastructureByteArrayWrapper** | [**kotlin.collections.List&lt;io.icure.kraken.client.infrastructure.ByteArrayWrapper&gt;**](io.icure.kraken.client.infrastructure.ByteArrayWrapper.md)|  |

### Return type

[**DocumentTemplateDto**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

<a name="setDocumentTemplateAttachmentJson"></a>
# **setDocumentTemplateAttachmentJson**
> DocumentTemplateDto setDocumentTemplateAttachmentJson(documentTemplateId, byteArrayDto)

Creates a document&#39;s attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentTemplateApi()
val documentTemplateId : kotlin.String = documentTemplateId_example // kotlin.String | 
val byteArrayDto : ByteArrayDto =  // ByteArrayDto | 
try {
    val result : DocumentTemplateDto = apiInstance.setDocumentTemplateAttachmentJson(documentTemplateId, byteArrayDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentTemplateApi#setDocumentTemplateAttachmentJson")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentTemplateApi#setDocumentTemplateAttachmentJson")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTemplateId** | **kotlin.String**|  |
 **byteArrayDto** | [**ByteArrayDto**](ByteArrayDto.md)|  |

### Return type

[**DocumentTemplateDto**](DocumentTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

