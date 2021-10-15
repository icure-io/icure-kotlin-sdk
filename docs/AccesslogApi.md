# AccessLogApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createAccessLog**](AccessLogApi.md#createAccessLog) | **POST** /rest/v2/accesslog | Creates an access log
[**deleteAccessLogs**](AccessLogApi.md#deleteAccessLogs) | **POST** /rest/v2/accesslog/delete/batch | Deletes an access log
[**findAccessLogsBy**](AccessLogApi.md#findAccessLogsBy) | **GET** /rest/v2/accesslog | Get Paginated List of Access logs
[**findAccessLogsByUserAfterDate**](AccessLogApi.md#findAccessLogsByUserAfterDate) | **GET** /rest/v2/accesslog/byUser | Get Paginated List of Access logs by user after date
[**getAccessLog**](AccessLogApi.md#getAccessLog) | **GET** /rest/v2/accesslog/{accessLogId} | Gets an access log
[**listAccessLogsByHCPartyAndPatientForeignKeys**](AccessLogApi.md#listAccessLogsByHCPartyAndPatientForeignKeys) | **GET** /rest/v2/accesslog/byHcPartySecretForeignKeys | List access logs found By Healthcare Party and secret foreign keyelementIds.
[**modifyAccessLog**](AccessLogApi.md#modifyAccessLog) | **PUT** /rest/v2/accesslog | Modifies an access log


<a name="createAccessLog"></a>
# **createAccessLog**
> AccessLogDto createAccessLog(accessLogDto)

Creates an access log

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AccessLogApi()
val accessLogDto : AccessLogDto =  // AccessLogDto | 
try {
    val result : AccessLogDto = apiInstance.createAccessLog(accessLogDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AccessLogApi#createAccessLog")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AccessLogApi#createAccessLog")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **accessLogDto** | [**AccessLogDto**](AccessLogDto.md)|  |

### Return type

[**AccessLogDto**](AccessLogDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteAccessLogs"></a>
# **deleteAccessLogs**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteAccessLogs(listOfIdsDto)

Deletes an access log

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AccessLogApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteAccessLogs(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AccessLogApi#deleteAccessLogs")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AccessLogApi#deleteAccessLogs")
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

<a name="findAccessLogsBy"></a>
# **findAccessLogsBy**
> PaginatedListAccessLogDto findAccessLogsBy(fromEpoch, toEpoch, startKey, startDocumentId, limit, descending)

Get Paginated List of Access logs

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AccessLogApi()
val fromEpoch : kotlin.Long = 789 // kotlin.Long | 
val toEpoch : kotlin.Long = 789 // kotlin.Long | 
val startKey : kotlin.Long = 789 // kotlin.Long | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
val descending : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : PaginatedListAccessLogDto = apiInstance.findAccessLogsBy(fromEpoch, toEpoch, startKey, startDocumentId, limit, descending)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AccessLogApi#findAccessLogsBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AccessLogApi#findAccessLogsBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fromEpoch** | **kotlin.Long**|  | [optional]
 **toEpoch** | **kotlin.Long**|  | [optional]
 **startKey** | **kotlin.Long**|  | [optional]
 **startDocumentId** | **kotlin.String**|  | [optional]
 **limit** | **kotlin.Int**|  | [optional]
 **descending** | **kotlin.Boolean**|  | [optional]

### Return type

[**PaginatedListAccessLogDto**](PaginatedListAccessLogDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findAccessLogsByUserAfterDate"></a>
# **findAccessLogsByUserAfterDate**
> PaginatedListAccessLogDto findAccessLogsByUserAfterDate(userId, accessType, startDate, startKey, startDocumentId, limit, descending)

Get Paginated List of Access logs by user after date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AccessLogApi()
val userId : kotlin.String = userId_example // kotlin.String | A User ID
val accessType : kotlin.String = accessType_example // kotlin.String | The type of access (COMPUTER or USER)
val startDate : kotlin.Long = 789 // kotlin.Long | The start search epoch
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val descending : kotlin.Boolean = true // kotlin.Boolean | Descending order
try {
    val result : PaginatedListAccessLogDto = apiInstance.findAccessLogsByUserAfterDate(userId, accessType, startDate, startKey, startDocumentId, limit, descending)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AccessLogApi#findAccessLogsByUserAfterDate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AccessLogApi#findAccessLogsByUserAfterDate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**| A User ID |
 **accessType** | **kotlin.String**| The type of access (COMPUTER or USER) | [optional]
 **startDate** | **kotlin.Long**| The start search epoch | [optional]
 **startKey** | **kotlin.String**| The start key for pagination | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]
 **descending** | **kotlin.Boolean**| Descending order | [optional]

### Return type

[**PaginatedListAccessLogDto**](PaginatedListAccessLogDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getAccessLog"></a>
# **getAccessLog**
> AccessLogDto getAccessLog(accessLogId)

Gets an access log

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AccessLogApi()
val accessLogId : kotlin.String = accessLogId_example // kotlin.String | 
try {
    val result : AccessLogDto = apiInstance.getAccessLog(accessLogId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AccessLogApi#getAccessLog")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AccessLogApi#getAccessLog")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **accessLogId** | **kotlin.String**|  |

### Return type

[**AccessLogDto**](AccessLogDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listAccessLogsByHCPartyAndPatientForeignKeys"></a>
# **listAccessLogsByHCPartyAndPatientForeignKeys**
> kotlin.collections.List&lt;AccessLogDto&gt; listAccessLogsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)

List access logs found By Healthcare Party and secret foreign keyelementIds.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AccessLogApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<AccessLogDto> = apiInstance.listAccessLogsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AccessLogApi#listAccessLogsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AccessLogApi#listAccessLogsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;AccessLogDto&gt;**](AccessLogDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyAccessLog"></a>
# **modifyAccessLog**
> AccessLogDto modifyAccessLog(accessLogDto)

Modifies an access log

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AccessLogApi()
val accessLogDto : AccessLogDto =  // AccessLogDto | 
try {
    val result : AccessLogDto = apiInstance.modifyAccessLog(accessLogDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AccessLogApi#modifyAccessLog")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AccessLogApi#modifyAccessLog")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **accessLogDto** | [**AccessLogDto**](AccessLogDto.md)|  |

### Return type

[**AccessLogDto**](AccessLogDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

