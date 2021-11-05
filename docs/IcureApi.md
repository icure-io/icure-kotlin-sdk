# IcureApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**getIndexingInfo**](IcureApi.md#getIndexingInfo) | **GET** /rest/v1/icure/i | Get index info
[**getProcessInfo**](IcureApi.md#getProcessInfo) | **GET** /rest/v1/icure/p | Get process info
[**getReplicationInfo**](IcureApi.md#getReplicationInfo) | **GET** /rest/v1/icure/r | Get replication info
[**getReplicatorInfo**](IcureApi.md#getReplicatorInfo) | **GET** /rest/v1/icure/r/{id} | Get replication info
[**getVersion**](IcureApi.md#getVersion) | **GET** /rest/v1/icure/v | Get version
[**isReady**](IcureApi.md#isReady) | **GET** /rest/v1/icure/ok | Check if a user exists
[**loglevel**](IcureApi.md#loglevel) | **POST** /rest/v1/icure/loglevel/{loglevel} | 
[**resolveContactsConflicts**](IcureApi.md#resolveContactsConflicts) | **POST** /rest/v1/icure/conflicts/contact | Resolve contacts conflicts
[**resolveDocumentsConflicts**](IcureApi.md#resolveDocumentsConflicts) | **POST** /rest/v1/icure/conflicts/document | resolve documents conflicts
[**resolveFormsConflicts**](IcureApi.md#resolveFormsConflicts) | **POST** /rest/v1/icure/conflicts/form | resolve forms conflicts
[**resolveHealthElementsConflicts**](IcureApi.md#resolveHealthElementsConflicts) | **POST** /rest/v1/icure/conflicts/healthelement | resolve healthcare elements conflicts
[**resolveInvoicesConflicts**](IcureApi.md#resolveInvoicesConflicts) | **POST** /rest/v1/icure/conflicts/invoice | resolve invoices conflicts
[**resolveMessagesConflicts**](IcureApi.md#resolveMessagesConflicts) | **POST** /rest/v1/icure/conflicts/message | resolve messages conflicts
[**resolvePatientsConflicts**](IcureApi.md#resolvePatientsConflicts) | **POST** /rest/v1/icure/conflicts/patient | Resolve patients conflicts
[**updateDesignDoc**](IcureApi.md#updateDesignDoc) | **POST** /rest/v1/icure/dd/{entityName} | Force update design doc


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

<a name="loglevel"></a>
# **loglevel**
> kotlin.String loglevel(loglevel, `package`)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = IcureApi()
val loglevel : kotlin.String = loglevel_example // kotlin.String | 
val `package` : kotlin.String = `package`_example // kotlin.String | 
try {
    val result : kotlin.String = apiInstance.loglevel(loglevel, `package`)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling IcureApi#loglevel")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling IcureApi#loglevel")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **loglevel** | **kotlin.String**|  |
 **&#x60;package&#x60;** | **kotlin.String**|  |

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

