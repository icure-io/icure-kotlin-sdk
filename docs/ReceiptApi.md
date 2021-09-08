# ReceiptApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createReceipt**](ReceiptApi.md#createReceipt) | **POST** /rest/v2/receipt | Creates a receipt
[**createReceipt1**](ReceiptApi.md#createReceipt1) | **POST** /rest/v1/receipt | Creates a receipt
[**deleteReceipt**](ReceiptApi.md#deleteReceipt) | **DELETE** /rest/v1/receipt/{receiptIds} | Deletes a receipt
[**deleteReceipts**](ReceiptApi.md#deleteReceipts) | **DELETE** /rest/v2/receipt/delete/batch | Deletes receipts
[**getReceipt**](ReceiptApi.md#getReceipt) | **GET** /rest/v2/receipt/{receiptId} | Gets a receipt
[**getReceipt1**](ReceiptApi.md#getReceipt1) | **GET** /rest/v1/receipt/{receiptId} | Gets a receipt
[**getReceiptAttachment**](ReceiptApi.md#getReceiptAttachment) | **GET** /rest/v2/receipt/{receiptId}/attachment/{attachmentId} | Get an attachment
[**getReceiptAttachment1**](ReceiptApi.md#getReceiptAttachment1) | **GET** /rest/v1/receipt/{receiptId}/attachment/{attachmentId} | Get an attachment
[**listByReference**](ReceiptApi.md#listByReference) | **GET** /rest/v2/receipt/byRef/{ref} | Gets a receipt
[**listByReference1**](ReceiptApi.md#listByReference1) | **GET** /rest/v1/receipt/byref/{ref} | Gets a receipt
[**modifyReceipt**](ReceiptApi.md#modifyReceipt) | **PUT** /rest/v2/receipt | Updates a receipt
[**modifyReceipt1**](ReceiptApi.md#modifyReceipt1) | **PUT** /rest/v1/receipt | Updates a receipt
[**setReceiptAttachment**](ReceiptApi.md#setReceiptAttachment) | **PUT** /rest/v2/receipt/{receiptId}/attachment/{blobType} | Creates a receipt&#39;s attachment
[**setReceiptAttachment1**](ReceiptApi.md#setReceiptAttachment1) | **PUT** /rest/v1/receipt/{receiptId}/attachment/{blobType} | Creates a receipt&#39;s attachment


<a name="createReceipt"></a>
# **createReceipt**
> ReceiptDto createReceipt(receiptDto)

Creates a receipt

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptDto : ReceiptDto =  // ReceiptDto | 
try {
    val result : ReceiptDto = apiInstance.createReceipt(receiptDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#createReceipt")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#createReceipt")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptDto** | [**ReceiptDto**](ReceiptDto.md)|  |

### Return type

[**ReceiptDto**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createReceipt1"></a>
# **createReceipt1**
> ReceiptDto createReceipt1(receiptDto)

Creates a receipt

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptDto : ReceiptDto =  // ReceiptDto | 
try {
    val result : ReceiptDto = apiInstance.createReceipt1(receiptDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#createReceipt1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#createReceipt1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptDto** | [**ReceiptDto**](ReceiptDto.md)|  |

### Return type

[**ReceiptDto**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteReceipt"></a>
# **deleteReceipt**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteReceipt(receiptIds)

Deletes a receipt

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptIds : kotlin.String = receiptIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteReceipt(receiptIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#deleteReceipt")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#deleteReceipt")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deleteReceipts"></a>
# **deleteReceipts**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteReceipts(listOfIdsDto)

Deletes receipts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteReceipts(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#deleteReceipts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#deleteReceipts")
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

<a name="getReceipt"></a>
# **getReceipt**
> ReceiptDto getReceipt(receiptId)

Gets a receipt

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptId : kotlin.String = receiptId_example // kotlin.String | 
try {
    val result : ReceiptDto = apiInstance.getReceipt(receiptId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#getReceipt")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#getReceipt")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptId** | **kotlin.String**|  |

### Return type

[**ReceiptDto**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getReceipt1"></a>
# **getReceipt1**
> ReceiptDto getReceipt1(receiptId)

Gets a receipt

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptId : kotlin.String = receiptId_example // kotlin.String | 
try {
    val result : ReceiptDto = apiInstance.getReceipt1(receiptId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#getReceipt1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#getReceipt1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptId** | **kotlin.String**|  |

### Return type

[**ReceiptDto**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getReceiptAttachment"></a>
# **getReceiptAttachment**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; getReceiptAttachment(receiptId, attachmentId, enckeys)

Get an attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptId : kotlin.String = receiptId_example // kotlin.String | 
val attachmentId : kotlin.String = attachmentId_example // kotlin.String | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.getReceiptAttachment(receiptId, attachmentId, enckeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#getReceiptAttachment")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#getReceiptAttachment")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptId** | **kotlin.String**|  |
 **attachmentId** | **kotlin.String**|  |
 **enckeys** | **kotlin.String**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

<a name="getReceiptAttachment1"></a>
# **getReceiptAttachment1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; getReceiptAttachment1(receiptId, attachmentId, enckeys)

Get an attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptId : kotlin.String = receiptId_example // kotlin.String | 
val attachmentId : kotlin.String = attachmentId_example // kotlin.String | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.getReceiptAttachment1(receiptId, attachmentId, enckeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#getReceiptAttachment1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#getReceiptAttachment1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptId** | **kotlin.String**|  |
 **attachmentId** | **kotlin.String**|  |
 **enckeys** | **kotlin.String**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

<a name="listByReference"></a>
# **listByReference**
> kotlin.collections.List&lt;ReceiptDto&gt; listByReference(ref)

Gets a receipt

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val ref : kotlin.String = ref_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ReceiptDto> = apiInstance.listByReference(ref)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#listByReference")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#listByReference")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ref** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ReceiptDto&gt;**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listByReference1"></a>
# **listByReference1**
> kotlin.collections.List&lt;ReceiptDto&gt; listByReference1(ref)

Gets a receipt

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val ref : kotlin.String = ref_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ReceiptDto> = apiInstance.listByReference1(ref)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#listByReference1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#listByReference1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ref** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ReceiptDto&gt;**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyReceipt"></a>
# **modifyReceipt**
> ReceiptDto modifyReceipt(receiptDto)

Updates a receipt

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptDto : ReceiptDto =  // ReceiptDto | 
try {
    val result : ReceiptDto = apiInstance.modifyReceipt(receiptDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#modifyReceipt")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#modifyReceipt")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptDto** | [**ReceiptDto**](ReceiptDto.md)|  |

### Return type

[**ReceiptDto**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyReceipt1"></a>
# **modifyReceipt1**
> ReceiptDto modifyReceipt1(receiptDto)

Updates a receipt

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptDto : ReceiptDto =  // ReceiptDto | 
try {
    val result : ReceiptDto = apiInstance.modifyReceipt1(receiptDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#modifyReceipt1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#modifyReceipt1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptDto** | [**ReceiptDto**](ReceiptDto.md)|  |

### Return type

[**ReceiptDto**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setReceiptAttachment"></a>
# **setReceiptAttachment**
> ReceiptDto setReceiptAttachment(receiptId, blobType, requestBody, enckeys)

Creates a receipt&#39;s attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptId : kotlin.String = receiptId_example // kotlin.String | 
val blobType : kotlin.String = blobType_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.ByteArray> =  // kotlin.collections.List<kotlin.ByteArray> | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
try {
    val result : ReceiptDto = apiInstance.setReceiptAttachment(receiptId, blobType, requestBody, enckeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#setReceiptAttachment")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#setReceiptAttachment")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptId** | **kotlin.String**|  |
 **blobType** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.ByteArray&gt;**](kotlin.ByteArray.md)|  |
 **enckeys** | **kotlin.String**|  | [optional]

### Return type

[**ReceiptDto**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

<a name="setReceiptAttachment1"></a>
# **setReceiptAttachment1**
> ReceiptDto setReceiptAttachment1(receiptId, blobType, body, enckeys)

Creates a receipt&#39;s attachment

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ReceiptApi()
val receiptId : kotlin.String = receiptId_example // kotlin.String | 
val blobType : kotlin.String = blobType_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
try {
    val result : ReceiptDto = apiInstance.setReceiptAttachment1(receiptId, blobType, body, enckeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ReceiptApi#setReceiptAttachment1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ReceiptApi#setReceiptAttachment1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **receiptId** | **kotlin.String**|  |
 **blobType** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |
 **enckeys** | **kotlin.String**|  | [optional]

### Return type

[**ReceiptDto**](ReceiptDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

