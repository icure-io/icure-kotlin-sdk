# MaintenanceTaskApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createMaintenanceTask**](MaintenanceTaskApi.md#createMaintenanceTask) | **POST** /rest/v2/maintenancetask | Creates a maintenanceTask
[**deleteMaintenanceTask**](MaintenanceTaskApi.md#deleteMaintenanceTask) | **DELETE** /rest/v2/maintenancetask/{maintenanceTaskIds} | Delete maintenanceTasks
[**filterMaintenanceTasksBy**](MaintenanceTaskApi.md#filterMaintenanceTasksBy) | **POST** /rest/v2/maintenancetask/filter | Filter maintenanceTasks for the current user (HcParty) 
[**getMaintenanceTask**](MaintenanceTaskApi.md#getMaintenanceTask) | **GET** /rest/v2/maintenancetask/{maintenanceTaskId} | Gets a maintenanceTask
[**modifyMaintenanceTask**](MaintenanceTaskApi.md#modifyMaintenanceTask) | **PUT** /rest/v2/maintenancetask | Updates a maintenanceTask


<a name="createMaintenanceTask"></a>
# **createMaintenanceTask**
> MaintenanceTaskDto createMaintenanceTask(maintenanceTaskDto)

Creates a maintenanceTask

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MaintenanceTaskApi()
val maintenanceTaskDto : MaintenanceTaskDto =  // MaintenanceTaskDto | 
try {
    val result : MaintenanceTaskDto = apiInstance.createMaintenanceTask(maintenanceTaskDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MaintenanceTaskApi#createMaintenanceTask")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MaintenanceTaskApi#createMaintenanceTask")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **maintenanceTaskDto** | [**MaintenanceTaskDto**](MaintenanceTaskDto.md)|  |

### Return type

[**MaintenanceTaskDto**](MaintenanceTaskDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteMaintenanceTask"></a>
# **deleteMaintenanceTask**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteMaintenanceTask(maintenanceTaskIds)

Delete maintenanceTasks

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MaintenanceTaskApi()
val maintenanceTaskIds : kotlin.String = maintenanceTaskIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteMaintenanceTask(maintenanceTaskIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MaintenanceTaskApi#deleteMaintenanceTask")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MaintenanceTaskApi#deleteMaintenanceTask")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **maintenanceTaskIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="filterMaintenanceTasksBy"></a>
# **filterMaintenanceTasksBy**
> PaginatedListMaintenanceTaskDto filterMaintenanceTasksBy(filterChainMaintenanceTask, startDocumentId, limit)

Filter maintenanceTasks for the current user (HcParty) 

Returns a list of maintenanceTasks along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MaintenanceTaskApi()
val filterChainMaintenanceTask : FilterChainMaintenanceTask =  // FilterChainMaintenanceTask | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A maintenanceTask document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListMaintenanceTaskDto = apiInstance.filterMaintenanceTasksBy(filterChainMaintenanceTask, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MaintenanceTaskApi#filterMaintenanceTasksBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MaintenanceTaskApi#filterMaintenanceTasksBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterChainMaintenanceTask** | [**FilterChainMaintenanceTask**](FilterChainMaintenanceTask.md)|  |
 **startDocumentId** | **kotlin.String**| A maintenanceTask document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListMaintenanceTaskDto**](PaginatedListMaintenanceTaskDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getMaintenanceTask"></a>
# **getMaintenanceTask**
> MaintenanceTaskDto getMaintenanceTask(maintenanceTaskId)

Gets a maintenanceTask

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MaintenanceTaskApi()
val maintenanceTaskId : kotlin.String = maintenanceTaskId_example // kotlin.String | 
try {
    val result : MaintenanceTaskDto = apiInstance.getMaintenanceTask(maintenanceTaskId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MaintenanceTaskApi#getMaintenanceTask")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MaintenanceTaskApi#getMaintenanceTask")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **maintenanceTaskId** | **kotlin.String**|  |

### Return type

[**MaintenanceTaskDto**](MaintenanceTaskDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyMaintenanceTask"></a>
# **modifyMaintenanceTask**
> MaintenanceTaskDto modifyMaintenanceTask(maintenanceTaskDto)

Updates a maintenanceTask

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MaintenanceTaskApi()
val maintenanceTaskDto : MaintenanceTaskDto =  // MaintenanceTaskDto | 
try {
    val result : MaintenanceTaskDto = apiInstance.modifyMaintenanceTask(maintenanceTaskDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MaintenanceTaskApi#modifyMaintenanceTask")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MaintenanceTaskApi#modifyMaintenanceTask")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **maintenanceTaskDto** | [**MaintenanceTaskDto**](MaintenanceTaskDto.md)|  |

### Return type

[**MaintenanceTaskDto**](MaintenanceTaskDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

