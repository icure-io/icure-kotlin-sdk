# CalendarItemTypeApi

All URIs are relative to *https://kraken.svc.icure.cloud*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createCalendarItemType**](CalendarItemTypeApi.md#createCalendarItemType) | **POST** /rest/v2/calendarItemType | Creates a calendarItemType
[**deleteCalendarItemTypes**](CalendarItemTypeApi.md#deleteCalendarItemTypes) | **POST** /rest/v2/calendarItemType/delete/batch | Deletes calendarItemTypes
[**getCalendarItemType**](CalendarItemTypeApi.md#getCalendarItemType) | **GET** /rest/v2/calendarItemType/{calendarItemTypeId} | Gets a calendarItemType
[**getCalendarItemTypes**](CalendarItemTypeApi.md#getCalendarItemTypes) | **GET** /rest/v2/calendarItemType | Gets all calendarItemTypes
[**getCalendarItemTypesIncludeDeleted**](CalendarItemTypeApi.md#getCalendarItemTypesIncludeDeleted) | **GET** /rest/v2/calendarItemType/includeDeleted | Gets all calendarItemTypes include deleted
[**modifyCalendarItemType**](CalendarItemTypeApi.md#modifyCalendarItemType) | **PUT** /rest/v2/calendarItemType | Modifies an calendarItemType


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

<a name="deleteCalendarItemTypes"></a>
# **deleteCalendarItemTypes**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteCalendarItemTypes(listOfIdsDto)

Deletes calendarItemTypes

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteCalendarItemTypes(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#deleteCalendarItemTypes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#deleteCalendarItemTypes")
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

<a name="getCalendarItemType"></a>
# **getCalendarItemType**
> CalendarItemTypeDto getCalendarItemType(calendarItemTypeId)

Gets a calendarItemType

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

