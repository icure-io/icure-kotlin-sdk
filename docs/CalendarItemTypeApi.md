# CalendarItemTypeApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createCalendarItemType**](CalendarItemTypeApi.md#createCalendarItemType) | **POST** /rest/v1/calendarItemType | Creates a calendarItemType
[**deleteCalendarItemType**](CalendarItemTypeApi.md#deleteCalendarItemType) | **DELETE** /rest/v1/calendarItemType/{calendarItemTypeIds} | Deletes an calendarItemType
[**getCalendarItemType**](CalendarItemTypeApi.md#getCalendarItemType) | **GET** /rest/v1/calendarItemType/{calendarItemTypeId} | Gets an calendarItemType
[**getCalendarItemTypes**](CalendarItemTypeApi.md#getCalendarItemTypes) | **GET** /rest/v1/calendarItemType | Gets all calendarItemTypes
[**getCalendarItemTypesIncludeDeleted**](CalendarItemTypeApi.md#getCalendarItemTypesIncludeDeleted) | **GET** /rest/v1/calendarItemType/includeDeleted | Gets all calendarItemTypes include deleted
[**modifyCalendarItemType**](CalendarItemTypeApi.md#modifyCalendarItemType) | **PUT** /rest/v1/calendarItemType | Modifies an calendarItemType


<a name="createCalendarItemType"></a>
# **createCalendarItemType**
> CalendarItemTypeDto createCalendarItemType(calendarItemTypeDto)

Creates a calendarItemType

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
val calendarItemTypeDto : CalendarItemTypeDto =  // CalendarItemTypeDto | 
try {
    val result : CalendarItemTypeDto = apiInstance.createCalendarItemType(calendarItemTypeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#createCalendarItemType")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#createCalendarItemType")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **calendarItemTypeDto** | [**CalendarItemTypeDto**](CalendarItemTypeDto.md)|  |

### Return type

[**CalendarItemTypeDto**](CalendarItemTypeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteCalendarItemType"></a>
# **deleteCalendarItemType**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteCalendarItemType(calendarItemTypeIds)

Deletes an calendarItemType

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
val calendarItemTypeIds : kotlin.String = calendarItemTypeIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteCalendarItemType(calendarItemTypeIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#deleteCalendarItemType")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#deleteCalendarItemType")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **calendarItemTypeIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCalendarItemType"></a>
# **getCalendarItemType**
> CalendarItemTypeDto getCalendarItemType(calendarItemTypeId)

Gets an calendarItemType

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
val calendarItemTypeId : kotlin.String = calendarItemTypeId_example // kotlin.String | 
try {
    val result : CalendarItemTypeDto = apiInstance.getCalendarItemType(calendarItemTypeId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#getCalendarItemType")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#getCalendarItemType")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **calendarItemTypeId** | **kotlin.String**|  |

### Return type

[**CalendarItemTypeDto**](CalendarItemTypeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCalendarItemTypes"></a>
# **getCalendarItemTypes**
> kotlin.collections.List&lt;CalendarItemTypeDto&gt; getCalendarItemTypes()

Gets all calendarItemTypes

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
try {
    val result : kotlin.collections.List<CalendarItemTypeDto> = apiInstance.getCalendarItemTypes()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#getCalendarItemTypes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#getCalendarItemTypes")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;CalendarItemTypeDto&gt;**](CalendarItemTypeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCalendarItemTypesIncludeDeleted"></a>
# **getCalendarItemTypesIncludeDeleted**
> kotlin.collections.List&lt;CalendarItemTypeDto&gt; getCalendarItemTypesIncludeDeleted()

Gets all calendarItemTypes include deleted

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
try {
    val result : kotlin.collections.List<CalendarItemTypeDto> = apiInstance.getCalendarItemTypesIncludeDeleted()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#getCalendarItemTypesIncludeDeleted")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#getCalendarItemTypesIncludeDeleted")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;CalendarItemTypeDto&gt;**](CalendarItemTypeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyCalendarItemType"></a>
# **modifyCalendarItemType**
> CalendarItemTypeDto modifyCalendarItemType(calendarItemTypeDto)

Modifies an calendarItemType

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
val calendarItemTypeDto : CalendarItemTypeDto =  // CalendarItemTypeDto | 
try {
    val result : CalendarItemTypeDto = apiInstance.modifyCalendarItemType(calendarItemTypeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#modifyCalendarItemType")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#modifyCalendarItemType")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **calendarItemTypeDto** | [**CalendarItemTypeDto**](CalendarItemTypeDto.md)|  |

### Return type

[**CalendarItemTypeDto**](CalendarItemTypeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

