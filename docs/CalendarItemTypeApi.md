# CalendarItemTypeApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createCalendarItemType**](CalendarItemTypeApi.md#createCalendarItemType) | **POST** /rest/v2/calendarItemType | Creates a calendarItemType
[**createCalendarItemType1**](CalendarItemTypeApi.md#createCalendarItemType1) | **POST** /rest/v1/calendarItemType | Creates a calendarItemType
[**deleteCalendarItemType**](CalendarItemTypeApi.md#deleteCalendarItemType) | **DELETE** /rest/v1/calendarItemType/{calendarItemTypeIds} | Deletes an calendarItemType
[**deleteCalendarItemTypes**](CalendarItemTypeApi.md#deleteCalendarItemTypes) | **POST** /rest/v2/calendarItemType/delete/batch | Deletes calendarItemTypes
[**getCalendarItemType**](CalendarItemTypeApi.md#getCalendarItemType) | **GET** /rest/v2/calendarItemType/{calendarItemTypeId} | Gets a calendarItemType
[**getCalendarItemType1**](CalendarItemTypeApi.md#getCalendarItemType1) | **GET** /rest/v1/calendarItemType/{calendarItemTypeId} | Gets an calendarItemType
[**getCalendarItemTypes**](CalendarItemTypeApi.md#getCalendarItemTypes) | **GET** /rest/v2/calendarItemType | Gets all calendarItemTypes
[**getCalendarItemTypes1**](CalendarItemTypeApi.md#getCalendarItemTypes1) | **GET** /rest/v1/calendarItemType | Gets all calendarItemTypes
[**getCalendarItemTypesIncludeDeleted**](CalendarItemTypeApi.md#getCalendarItemTypesIncludeDeleted) | **GET** /rest/v2/calendarItemType/includeDeleted | Gets all calendarItemTypes include deleted
[**getCalendarItemTypesIncludeDeleted1**](CalendarItemTypeApi.md#getCalendarItemTypesIncludeDeleted1) | **GET** /rest/v1/calendarItemType/includeDeleted | Gets all calendarItemTypes include deleted
[**modifyCalendarItemType**](CalendarItemTypeApi.md#modifyCalendarItemType) | **PUT** /rest/v2/calendarItemType | Modifies an calendarItemType
[**modifyCalendarItemType1**](CalendarItemTypeApi.md#modifyCalendarItemType1) | **PUT** /rest/v1/calendarItemType | Modifies an calendarItemType


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

<a name="createCalendarItemType1"></a>
# **createCalendarItemType1**
> CalendarItemTypeDto createCalendarItemType1(calendarItemTypeDto)

Creates a calendarItemType

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
val calendarItemTypeDto : CalendarItemTypeDto =  // CalendarItemTypeDto | 
try {
    val result : CalendarItemTypeDto = apiInstance.createCalendarItemType1(calendarItemTypeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#createCalendarItemType1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#createCalendarItemType1")
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

<a name="getCalendarItemType1"></a>
# **getCalendarItemType1**
> CalendarItemTypeDto getCalendarItemType1(calendarItemTypeId)

Gets an calendarItemType

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
val calendarItemTypeId : kotlin.String = calendarItemTypeId_example // kotlin.String | 
try {
    val result : CalendarItemTypeDto = apiInstance.getCalendarItemType1(calendarItemTypeId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#getCalendarItemType1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#getCalendarItemType1")
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

<a name="getCalendarItemTypes1"></a>
# **getCalendarItemTypes1**
> kotlin.collections.List&lt;CalendarItemTypeDto&gt; getCalendarItemTypes1()

Gets all calendarItemTypes

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
try {
    val result : kotlin.collections.List<CalendarItemTypeDto> = apiInstance.getCalendarItemTypes1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#getCalendarItemTypes1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#getCalendarItemTypes1")
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

<a name="getCalendarItemTypesIncludeDeleted1"></a>
# **getCalendarItemTypesIncludeDeleted1**
> kotlin.collections.List&lt;CalendarItemTypeDto&gt; getCalendarItemTypesIncludeDeleted1()

Gets all calendarItemTypes include deleted

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
try {
    val result : kotlin.collections.List<CalendarItemTypeDto> = apiInstance.getCalendarItemTypesIncludeDeleted1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#getCalendarItemTypesIncludeDeleted1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#getCalendarItemTypesIncludeDeleted1")
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

<a name="modifyCalendarItemType1"></a>
# **modifyCalendarItemType1**
> CalendarItemTypeDto modifyCalendarItemType1(calendarItemTypeDto)

Modifies an calendarItemType

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemTypeApi()
val calendarItemTypeDto : CalendarItemTypeDto =  // CalendarItemTypeDto | 
try {
    val result : CalendarItemTypeDto = apiInstance.modifyCalendarItemType1(calendarItemTypeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemTypeApi#modifyCalendarItemType1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemTypeApi#modifyCalendarItemType1")
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

