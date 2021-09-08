# IcureApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**getIndexingInfo**](IcureApi.md#getIndexingInfo) | **GET** /rest/v2/icure/i | Get index info
[**getIndexingInfo1**](IcureApi.md#getIndexingInfo1) | **GET** /rest/v1/icure/i | Get index info
[**getProcessInfo**](IcureApi.md#getProcessInfo) | **GET** /rest/v2/icure/p | Get process info
[**getProcessInfo1**](IcureApi.md#getProcessInfo1) | **GET** /rest/v1/icure/p | Get process info
[**getReplicationInfo**](IcureApi.md#getReplicationInfo) | **GET** /rest/v2/icure/r | Get replication info
[**getReplicationInfo1**](IcureApi.md#getReplicationInfo1) | **GET** /rest/v1/icure/r | Get replication info
[**getReplicatorInfo**](IcureApi.md#getReplicatorInfo) | **GET** /rest/v2/icure/r/{id} | Get replication info
[**getReplicatorInfo1**](IcureApi.md#getReplicatorInfo1) | **GET** /rest/v1/icure/r/{id} | Get replication info
[**getVersion**](IcureApi.md#getVersion) | **GET** /rest/v2/icure/v | Get version
[**getVersion1**](IcureApi.md#getVersion1) | **GET** /rest/v1/icure/v | Get version
[**isReady**](IcureApi.md#isReady) | **GET** /rest/v2/icure/ok | Check if a user exists
[**isReady1**](IcureApi.md#isReady1) | **GET** /rest/v1/icure/ok | Check if a user exists
[**resolveContactsConflicts**](IcureApi.md#resolveContactsConflicts) | **POST** /rest/v2/icure/conflicts/contact | Resolve contacts conflicts
[**resolveContactsConflicts1**](IcureApi.md#resolveContactsConflicts1) | **POST** /rest/v1/icure/conflicts/contact | Resolve contacts conflicts
[**resolveDocumentsConflicts**](IcureApi.md#resolveDocumentsConflicts) | **POST** /rest/v2/icure/conflicts/document | resolve documents conflicts
[**resolveDocumentsConflicts1**](IcureApi.md#resolveDocumentsConflicts1) | **POST** /rest/v1/icure/conflicts/document | resolve documents conflicts
[**resolveFormsConflicts**](IcureApi.md#resolveFormsConflicts) | **POST** /rest/v2/icure/conflicts/form | resolve forms conflicts
[**resolveFormsConflicts1**](IcureApi.md#resolveFormsConflicts1) | **POST** /rest/v1/icure/conflicts/form | resolve forms conflicts
[**resolveHealthElementsConflicts**](IcureApi.md#resolveHealthElementsConflicts) | **POST** /rest/v2/icure/conflicts/healthelement | resolve healthcare elements conflicts
[**resolveHealthElementsConflicts1**](IcureApi.md#resolveHealthElementsConflicts1) | **POST** /rest/v1/icure/conflicts/healthelement | resolve healthcare elements conflicts
[**resolveInvoicesConflicts**](IcureApi.md#resolveInvoicesConflicts) | **POST** /rest/v2/icure/conflicts/invoice | resolve invoices conflicts
[**resolveInvoicesConflicts1**](IcureApi.md#resolveInvoicesConflicts1) | **POST** /rest/v1/icure/conflicts/invoice | resolve invoices conflicts
[**resolveMessagesConflicts**](IcureApi.md#resolveMessagesConflicts) | **POST** /rest/v2/icure/conflicts/message | resolve messages conflicts
[**resolveMessagesConflicts1**](IcureApi.md#resolveMessagesConflicts1) | **POST** /rest/v1/icure/conflicts/message | resolve messages conflicts
[**resolvePatientsConflicts**](IcureApi.md#resolvePatientsConflicts) | **POST** /rest/v2/icure/conflicts/patient | Resolve patients conflicts
[**resolvePatientsConflicts1**](IcureApi.md#resolvePatientsConflicts1) | **POST** /rest/v1/icure/conflicts/patient | Resolve patients conflicts
[**updateDesignDoc**](IcureApi.md#updateDesignDoc) | **POST** /rest/v2/icure/dd/{entityName} | Force update design doc
[**updateDesignDoc1**](IcureApi.md#updateDesignDoc1) | **POST** /rest/v1/icure/dd/{entityName} | Force update design doc


<a name="getIndexingInfo"></a>
# **getIndexingInfo**
> IndexingInfoDto getIndexingInfo()

Get index info

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : IndexingInfoDto = apiInstance.getIndexingInfo()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getIndexingInfo")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getIndexingInfo")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**IndexingInfoDto**](IndexingInfoDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getIndexingInfo1"></a>
# **getIndexingInfo1**
> IndexingInfoDto getIndexingInfo1()

Get index info

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : IndexingInfoDto = apiInstance.getIndexingInfo1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getIndexingInfo1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getIndexingInfo1")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**IndexingInfoDto**](IndexingInfoDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getProcessInfo"></a>
# **getProcessInfo**
> kotlin.String getProcessInfo()

Get process info

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : kotlin.String = apiInstance.getProcessInfo()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getProcessInfo")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getProcessInfo")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/plain

<a name="getProcessInfo1"></a>
# **getProcessInfo1**
> kotlin.String getProcessInfo1()

Get process info

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : kotlin.String = apiInstance.getProcessInfo1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getProcessInfo1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getProcessInfo1")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/plain

<a name="getReplicationInfo"></a>
# **getReplicationInfo**
> ReplicationInfoDto getReplicationInfo()

Get replication info

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : ReplicationInfoDto = apiInstance.getReplicationInfo()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getReplicationInfo")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getReplicationInfo")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**ReplicationInfoDto**](ReplicationInfoDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getReplicationInfo1"></a>
# **getReplicationInfo1**
> ReplicationInfoDto getReplicationInfo1()

Get replication info

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : ReplicationInfoDto = apiInstance.getReplicationInfo1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getReplicationInfo1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getReplicationInfo1")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**ReplicationInfoDto**](ReplicationInfoDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getReplicatorInfo"></a>
# **getReplicatorInfo**
> ReplicatorDocument getReplicatorInfo(id)

Get replication info

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : ReplicatorDocument = apiInstance.getReplicatorInfo(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getReplicatorInfo")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getReplicatorInfo")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**ReplicatorDocument**](ReplicatorDocument.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getReplicatorInfo1"></a>
# **getReplicatorInfo1**
> ReplicatorDocument getReplicatorInfo1(id)

Get replication info

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : ReplicatorDocument = apiInstance.getReplicatorInfo1(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getReplicatorInfo1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getReplicatorInfo1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**ReplicatorDocument**](ReplicatorDocument.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getVersion"></a>
# **getVersion**
> kotlin.String getVersion()

Get version

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : kotlin.String = apiInstance.getVersion()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getVersion")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getVersion")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/plain

<a name="getVersion1"></a>
# **getVersion1**
> kotlin.String getVersion1()

Get version

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : kotlin.String = apiInstance.getVersion1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#getVersion1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#getVersion1")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/plain

<a name="isReady"></a>
# **isReady**
> kotlin.String isReady()

Check if a user exists

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : kotlin.String = apiInstance.isReady()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#isReady")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#isReady")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/plain

<a name="isReady1"></a>
# **isReady1**
> kotlin.String isReady1()

Check if a user exists

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
try {
    val result : kotlin.String = apiInstance.isReady1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#isReady1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#isReady1")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/plain

<a name="resolveContactsConflicts"></a>
# **resolveContactsConflicts**
> kotlin.collections.List&lt;ContactDto&gt; resolveContactsConflicts(limit)

Resolve contacts conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.resolveContactsConflicts(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveContactsConflicts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveContactsConflicts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveContactsConflicts1"></a>
# **resolveContactsConflicts1**
> kotlin.collections.List&lt;ContactDto&gt; resolveContactsConflicts1(limit)

Resolve contacts conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.resolveContactsConflicts1(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveContactsConflicts1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveContactsConflicts1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveDocumentsConflicts"></a>
# **resolveDocumentsConflicts**
> kotlin.collections.List&lt;DocumentDto&gt; resolveDocumentsConflicts(ids, limit)

resolve documents conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val ids : kotlin.String = ids_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.resolveDocumentsConflicts(ids, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveDocumentsConflicts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveDocumentsConflicts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ids** | **kotlin.String**|  | [optional]
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveDocumentsConflicts1"></a>
# **resolveDocumentsConflicts1**
> kotlin.collections.List&lt;DocumentDto&gt; resolveDocumentsConflicts1(ids, limit)

resolve documents conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val ids : kotlin.String = ids_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.resolveDocumentsConflicts1(ids, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveDocumentsConflicts1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveDocumentsConflicts1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ids** | **kotlin.String**|  | [optional]
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveFormsConflicts"></a>
# **resolveFormsConflicts**
> kotlin.collections.List&lt;FormDto&gt; resolveFormsConflicts(limit)

resolve forms conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.resolveFormsConflicts(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveFormsConflicts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveFormsConflicts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveFormsConflicts1"></a>
# **resolveFormsConflicts1**
> kotlin.collections.List&lt;FormDto&gt; resolveFormsConflicts1(limit)

resolve forms conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.resolveFormsConflicts1(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveFormsConflicts1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveFormsConflicts1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveHealthElementsConflicts"></a>
# **resolveHealthElementsConflicts**
> kotlin.collections.List&lt;HealthElementDto&gt; resolveHealthElementsConflicts(limit)

resolve healthcare elements conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.resolveHealthElementsConflicts(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveHealthElementsConflicts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveHealthElementsConflicts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveHealthElementsConflicts1"></a>
# **resolveHealthElementsConflicts1**
> kotlin.collections.List&lt;HealthElementDto&gt; resolveHealthElementsConflicts1(limit)

resolve healthcare elements conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.resolveHealthElementsConflicts1(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveHealthElementsConflicts1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveHealthElementsConflicts1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveInvoicesConflicts"></a>
# **resolveInvoicesConflicts**
> kotlin.collections.List&lt;InvoiceDto&gt; resolveInvoicesConflicts(limit)

resolve invoices conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.resolveInvoicesConflicts(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveInvoicesConflicts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveInvoicesConflicts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveInvoicesConflicts1"></a>
# **resolveInvoicesConflicts1**
> kotlin.collections.List&lt;InvoiceDto&gt; resolveInvoicesConflicts1(limit)

resolve invoices conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.resolveInvoicesConflicts1(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveInvoicesConflicts1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveInvoicesConflicts1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveMessagesConflicts"></a>
# **resolveMessagesConflicts**
> kotlin.collections.List&lt;MessageDto&gt; resolveMessagesConflicts(limit)

resolve messages conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.resolveMessagesConflicts(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveMessagesConflicts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveMessagesConflicts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolveMessagesConflicts1"></a>
# **resolveMessagesConflicts1**
> kotlin.collections.List&lt;MessageDto&gt; resolveMessagesConflicts1(limit)

resolve messages conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.resolveMessagesConflicts1(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolveMessagesConflicts1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolveMessagesConflicts1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolvePatientsConflicts"></a>
# **resolvePatientsConflicts**
> kotlin.collections.List&lt;PatientDto&gt; resolvePatientsConflicts(limit)

Resolve patients conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<PatientDto> = apiInstance.resolvePatientsConflicts(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolvePatientsConflicts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolvePatientsConflicts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="resolvePatientsConflicts1"></a>
# **resolvePatientsConflicts1**
> kotlin.collections.List&lt;PatientDto&gt; resolvePatientsConflicts1(limit)

Resolve patients conflicts

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<PatientDto> = apiInstance.resolvePatientsConflicts1(limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#resolvePatientsConflicts1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#resolvePatientsConflicts1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="updateDesignDoc"></a>
# **updateDesignDoc**
> kotlin.Boolean updateDesignDoc(entityName, warmup)

Force update design doc

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val entityName : kotlin.String = entityName_example // kotlin.String | 
val warmup : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.Boolean = apiInstance.updateDesignDoc(entityName, warmup)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#updateDesignDoc")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#updateDesignDoc")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityName** | **kotlin.String**|  |
 **warmup** | **kotlin.Boolean**|  | [optional]

### Return type

**kotlin.Boolean**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="updateDesignDoc1"></a>
# **updateDesignDoc1**
> kotlin.Boolean updateDesignDoc1(entityName, warmup)

Force update design doc

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val entityName : kotlin.String = entityName_example // kotlin.String | 
val warmup : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.Boolean = apiInstance.updateDesignDoc1(entityName, warmup)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#updateDesignDoc1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#updateDesignDoc1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityName** | **kotlin.String**|  |
 **warmup** | **kotlin.Boolean**|  | [optional]

### Return type

**kotlin.Boolean**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

