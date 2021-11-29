# DocumentApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createDocument**](DocumentApi.md#createDocument) | **POST** /rest/v1/document | Create a document
[**deleteAttachment**](DocumentApi.md#deleteAttachment) | **DELETE** /rest/v1/document/{documentId}/attachment | Delete a document&#39;s attachment
[**deleteDocument**](DocumentApi.md#deleteDocument) | **DELETE** /rest/v1/document/{documentIds} | Delete a document
[**findByTypeHCPartyMessageSecretFKeys**](DocumentApi.md#findByTypeHCPartyMessageSecretFKeys) | **GET** /rest/v1/document/byTypeHcPartySecretForeignKeys | List documents found By type, By Healthcare Party and secret foreign keys.
[**findDocumentsByHCPartyPatientForeignKeys**](DocumentApi.md#findDocumentsByHCPartyPatientForeignKeys) | **GET** /rest/v1/document/byHcPartySecretForeignKeys | List documents found By Healthcare Party and secret foreign keys.
[**findWithoutDelegation**](DocumentApi.md#findWithoutDelegation) | **GET** /rest/v1/document/woDelegation | List documents with no delegation
[**getDocument**](DocumentApi.md#getDocument) | **GET** /rest/v1/document/{documentId} | Get a document
[**getDocumentAttachment**](DocumentApi.md#getDocumentAttachment) | **GET** /rest/v1/document/{documentId}/attachment/{attachmentId} | Load document&#39;s attachment
[**getDocumentByExternalUuid**](DocumentApi.md#getDocumentByExternalUuid) | **GET** /rest/v1/document/externaluuid/{externalUuid} | Get a document
[**getDocuments**](DocumentApi.md#getDocuments) | **POST** /rest/v1/document/batch | Get a batch of document
[**getDocumentsByExternalUuid**](DocumentApi.md#getDocumentsByExternalUuid) | **GET** /rest/v1/document/externaluuid/{externalUuid}/all | Get all documents with externalUuid
[**modifyDocument**](DocumentApi.md#modifyDocument) | **PUT** /rest/v1/document | Update a document
[**modifyDocuments**](DocumentApi.md#modifyDocuments) | **PUT** /rest/v1/document/batch | Update a batch of documents
[**setDocumentAttachment**](DocumentApi.md#setDocumentAttachment) | **PUT** /rest/v1/document/{documentId}/attachment | Create a document&#39;s attachment
[**setDocumentAttachmentBody**](DocumentApi.md#setDocumentAttachmentBody) | **PUT** /rest/v1/document/attachment | Create a document&#39;s attachment
[**setDocumentAttachmentMulti**](DocumentApi.md#setDocumentAttachmentMulti) | **PUT** /rest/v1/document/{documentId}/attachment/multipart | Creates a document&#39;s attachment
[**setDocumentsDelegations**](DocumentApi.md#setDocumentsDelegations) | **POST** /rest/v1/document/delegations | Update delegations in healthElements.


<a name="createDocument"></a>
# **createDocument**
> DocumentDto createDocument(documentDto)

Create a document

Creates a document and returns an instance of created document afterward

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentDto : DocumentDto =  // DocumentDto | 
try {
    val result : DocumentDto = apiInstance.createDocument(documentDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#createDocument")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#createDocument")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentDto** | [**DocumentDto**](DocumentDto.md)|  |

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteAttachment"></a>
# **deleteAttachment**
> DocumentDto deleteAttachment(documentId)

Delete a document&#39;s attachment

Deletes a document&#39;s attachment and returns the modified document instance afterward

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
try {
    val result : DocumentDto = apiInstance.deleteAttachment(documentId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#deleteAttachment")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#deleteAttachment")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deleteDocument"></a>
# **deleteDocument**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteDocument(documentIds)

Delete a document

Deletes a batch of documents and returns the list of deleted document ids

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentIds : kotlin.String = documentIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteDocument(documentIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#deleteDocument")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#deleteDocument")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findByTypeHCPartyMessageSecretFKeys"></a>
# **findByTypeHCPartyMessageSecretFKeys**
> kotlin.collections.List&lt;DocumentDto&gt; findByTypeHCPartyMessageSecretFKeys(documentTypeCode, hcPartyId, secretFKeys)

List documents found By type, By Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentTypeCode : kotlin.String = documentTypeCode_example // kotlin.String | 
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.findByTypeHCPartyMessageSecretFKeys(documentTypeCode, hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#findByTypeHCPartyMessageSecretFKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#findByTypeHCPartyMessageSecretFKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentTypeCode** | **kotlin.String**|  |
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findDocumentsByHCPartyPatientForeignKeys"></a>
# **findDocumentsByHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;DocumentDto&gt; findDocumentsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)

List documents found By Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.findDocumentsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#findDocumentsByHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#findDocumentsByHCPartyPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findWithoutDelegation"></a>
# **findWithoutDelegation**
> kotlin.collections.List&lt;DocumentDto&gt; findWithoutDelegation(limit)

List documents with no delegation

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.findWithoutDelegation(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#findWithoutDelegation")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#findWithoutDelegation")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getDocument"></a>
# **getDocument**
> DocumentDto getDocument(documentId)

Get a document

Returns the document corresponding to the identifier passed in the request

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
try {
    val result : DocumentDto = apiInstance.getDocument(documentId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#getDocument")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#getDocument")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getDocumentAttachment"></a>
# **getDocumentAttachment**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; getDocumentAttachment(documentId, attachmentId, enckeys, fileName)

Load document&#39;s attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val attachmentId : kotlin.String = attachmentId_example // kotlin.String | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
val fileName : kotlin.String = fileName_example // kotlin.String | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.getDocumentAttachment(documentId, attachmentId, enckeys, fileName)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#getDocumentAttachment")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#getDocumentAttachment")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **attachmentId** | **kotlin.String**|  |
 **enckeys** | **kotlin.String**|  | [optional]
 **fileName** | **kotlin.String**|  | [optional]

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

<a name="getDocumentByExternalUuid"></a>
# **getDocumentByExternalUuid**
> DocumentDto getDocumentByExternalUuid(externalUuid)

Get a document

Returns the first document corresponding to the externalUuid passed in the request

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val externalUuid : kotlin.String = externalUuid_example // kotlin.String | 
try {
    val result : DocumentDto = apiInstance.getDocumentByExternalUuid(externalUuid)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#getDocumentByExternalUuid")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#getDocumentByExternalUuid")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **externalUuid** | **kotlin.String**|  |

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getDocuments"></a>
# **getDocuments**
> kotlin.collections.List&lt;DocumentDto&gt; getDocuments(listOfIdsDto)

Get a batch of document

Returns a list of document corresponding to the identifiers passed in the body

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.getDocuments(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#getDocuments")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#getDocuments")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getDocumentsByExternalUuid"></a>
# **getDocumentsByExternalUuid**
> kotlin.collections.List&lt;DocumentDto&gt; getDocumentsByExternalUuid(externalUuid)

Get all documents with externalUuid

Returns a list of document corresponding to the externalUuid passed in the request

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val externalUuid : kotlin.String = externalUuid_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.getDocumentsByExternalUuid(externalUuid)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#getDocumentsByExternalUuid")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#getDocumentsByExternalUuid")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **externalUuid** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyDocument"></a>
# **modifyDocument**
> DocumentDto modifyDocument(documentDto)

Update a document

Updates the document and returns an instance of the modified document afterward

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentDto : DocumentDto =  // DocumentDto | 
try {
    val result : DocumentDto = apiInstance.modifyDocument(documentDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#modifyDocument")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#modifyDocument")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentDto** | [**DocumentDto**](DocumentDto.md)|  |

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyDocuments"></a>
# **modifyDocuments**
> kotlin.collections.List&lt;DocumentDto&gt; modifyDocuments(documentDto)

Update a batch of documents

Returns the modified documents.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentDto : kotlin.collections.List<DocumentDto> =  // kotlin.collections.List<DocumentDto> | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.modifyDocuments(documentDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#modifyDocuments")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#modifyDocuments")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentDto** | [**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)|  |

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setDocumentAttachment"></a>
# **setDocumentAttachment**
> DocumentDto setDocumentAttachment(documentId, body, enckeys)

Create a document&#39;s attachment

Creates a document&#39;s attachment and returns the modified document instance afterward

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
try {
    val result : DocumentDto = apiInstance.setDocumentAttachment(documentId, body, enckeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#setDocumentAttachment")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#setDocumentAttachment")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |
 **enckeys** | **kotlin.String**|  | [optional]

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

<a name="setDocumentAttachmentBody"></a>
# **setDocumentAttachmentBody**
> DocumentDto setDocumentAttachmentBody(documentId, body, enckeys)

Create a document&#39;s attachment

Creates a document attachment and returns the modified document instance afterward

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
try {
    val result : DocumentDto = apiInstance.setDocumentAttachmentBody(documentId, body, enckeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#setDocumentAttachmentBody")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#setDocumentAttachmentBody")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |
 **enckeys** | **kotlin.String**|  | [optional]

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

<a name="setDocumentAttachmentMulti"></a>
# **setDocumentAttachmentMulti**
> DocumentDto setDocumentAttachmentMulti(documentId, attachment, enckeys)

Creates a document&#39;s attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val attachment : kotlin.collections.List<kotlin.ByteArray> = BYTE_ARRAY_DATA_HERE // kotlin.collections.List<kotlin.ByteArray> | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
try {
    val result : DocumentDto = apiInstance.setDocumentAttachmentMulti(documentId, attachment, enckeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#setDocumentAttachmentMulti")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#setDocumentAttachmentMulti")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **attachment** | [**kotlin.collections.List&lt;kotlin.ByteArray&gt;**](kotlin.ByteArray.md)|  |
 **enckeys** | **kotlin.String**|  | [optional]

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: multipart/form-data
 - **Accept**: */*

<a name="setDocumentsDelegations"></a>
# **setDocumentsDelegations**
> kotlin.collections.List&lt;IcureStubDto&gt; setDocumentsDelegations(icureStubDto)

Update delegations in healthElements.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DocumentApi()
val icureStubDto : kotlin.collections.List<IcureStubDto> =  // kotlin.collections.List<IcureStubDto> | 
try {
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.setDocumentsDelegations(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DocumentApi#setDocumentsDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DocumentApi#setDocumentsDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **icureStubDto** | [**kotlin.collections.List&lt;IcureStubDto&gt;**](IcureStubDto.md)|  |

### Return type

[**kotlin.collections.List&lt;IcureStubDto&gt;**](IcureStubDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

