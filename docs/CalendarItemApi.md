# CalendarItemApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createCalendarItem**](CalendarItemApi.md#createCalendarItem) | **POST** /rest/v1/calendarItem | Creates a calendarItem
[**deleteCalendarItem**](CalendarItemApi.md#deleteCalendarItem) | **DELETE** /rest/v1/calendarItem/{calendarItemIds} | Deletes an calendarItem
[**findCalendarItemsByHCPartyPatientForeignKeys**](CalendarItemApi.md#findCalendarItemsByHCPartyPatientForeignKeys) | **GET** /rest/v1/calendarItem/byHcPartySecretForeignKeys | Find CalendarItems by hcparty and patient
[**getCalendarItem**](CalendarItemApi.md#getCalendarItem) | **GET** /rest/v1/calendarItem/{calendarItemId} | Gets an calendarItem
[**getCalendarItems**](CalendarItemApi.md#getCalendarItems) | **GET** /rest/v1/calendarItem | Gets all calendarItems
[**getCalendarItemsByPeriodAndHcPartyId**](CalendarItemApi.md#getCalendarItemsByPeriodAndHcPartyId) | **POST** /rest/v1/calendarItem/byPeriodAndHcPartyId | Get CalendarItems by Period and HcPartyId
[**getCalendarItemsWithIds**](CalendarItemApi.md#getCalendarItemsWithIds) | **POST** /rest/v1/calendarItem/byIds | Get calendarItems by id
[**getCalendarsByPeriodAndAgendaId**](CalendarItemApi.md#getCalendarsByPeriodAndAgendaId) | **POST** /rest/v1/calendarItem/byPeriodAndAgendaId | Get CalendarItems by Period and AgendaId
[**modifyCalendarItem**](CalendarItemApi.md#modifyCalendarItem) | **PUT** /rest/v1/calendarItem | Modifies an calendarItem
[**setCalendarItemsDelegations**](CalendarItemApi.md#setCalendarItemsDelegations) | **POST** /rest/v1/calendarItem/delegations | Update delegations in calendarItems


<a name="createCalendarItem"></a>
# **createCalendarItem**
> CalendarItemDto createCalendarItem(calendarItemDto)

Creates a calendarItem

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val calendarItemDto : CalendarItemDto =  // CalendarItemDto | 
try {
    val result : CalendarItemDto = apiInstance.createCalendarItem(calendarItemDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#createCalendarItem")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#createCalendarItem")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **calendarItemDto** | [**CalendarItemDto**](CalendarItemDto.md)|  |

### Return type

[**CalendarItemDto**](CalendarItemDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteCalendarItem"></a>
# **deleteCalendarItem**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteCalendarItem(calendarItemIds)

Deletes an calendarItem

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val calendarItemIds : kotlin.String = calendarItemIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteCalendarItem(calendarItemIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#deleteCalendarItem")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#deleteCalendarItem")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **calendarItemIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findCalendarItemsByHCPartyPatientForeignKeys"></a>
# **findCalendarItemsByHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;CalendarItemDto&gt; findCalendarItemsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)

Find CalendarItems by hcparty and patient

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.findCalendarItemsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#findCalendarItemsByHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#findCalendarItemsByHCPartyPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;CalendarItemDto&gt;**](CalendarItemDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCalendarItem"></a>
# **getCalendarItem**
> CalendarItemDto getCalendarItem(calendarItemId)

Gets an calendarItem

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val calendarItemId : kotlin.String = calendarItemId_example // kotlin.String | 
try {
    val result : CalendarItemDto = apiInstance.getCalendarItem(calendarItemId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarItem")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarItem")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **calendarItemId** | **kotlin.String**|  |

### Return type

[**CalendarItemDto**](CalendarItemDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCalendarItems"></a>
# **getCalendarItems**
> kotlin.collections.List&lt;CalendarItemDto&gt; getCalendarItems()

Gets all calendarItems

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
try {
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.getCalendarItems()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarItems")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarItems")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;CalendarItemDto&gt;**](CalendarItemDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCalendarItemsByPeriodAndHcPartyId"></a>
# **getCalendarItemsByPeriodAndHcPartyId**
> kotlin.collections.List&lt;CalendarItemDto&gt; getCalendarItemsByPeriodAndHcPartyId(startDate, endDate, hcPartyId)

Get CalendarItems by Period and HcPartyId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val startDate : kotlin.Long = 789 // kotlin.Long | 
val endDate : kotlin.Long = 789 // kotlin.Long | 
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.getCalendarItemsByPeriodAndHcPartyId(startDate, endDate, hcPartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarItemsByPeriodAndHcPartyId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarItemsByPeriodAndHcPartyId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startDate** | **kotlin.Long**|  |
 **endDate** | **kotlin.Long**|  |
 **hcPartyId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;CalendarItemDto&gt;**](CalendarItemDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCalendarItemsWithIds"></a>
# **getCalendarItemsWithIds**
> kotlin.collections.List&lt;CalendarItemDto&gt; getCalendarItemsWithIds(listOfIdsDto)

Get calendarItems by id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.getCalendarItemsWithIds(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarItemsWithIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarItemsWithIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;CalendarItemDto&gt;**](CalendarItemDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getCalendarsByPeriodAndAgendaId"></a>
# **getCalendarsByPeriodAndAgendaId**
> kotlin.collections.List&lt;CalendarItemDto&gt; getCalendarsByPeriodAndAgendaId(startDate, endDate, agendaId)

Get CalendarItems by Period and AgendaId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val startDate : kotlin.Long = 789 // kotlin.Long | 
val endDate : kotlin.Long = 789 // kotlin.Long | 
val agendaId : kotlin.String = agendaId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.getCalendarsByPeriodAndAgendaId(startDate, endDate, agendaId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarsByPeriodAndAgendaId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarsByPeriodAndAgendaId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startDate** | **kotlin.Long**|  |
 **endDate** | **kotlin.Long**|  |
 **agendaId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;CalendarItemDto&gt;**](CalendarItemDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyCalendarItem"></a>
# **modifyCalendarItem**
> CalendarItemDto modifyCalendarItem(calendarItemDto)

Modifies an calendarItem

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val calendarItemDto : CalendarItemDto =  // CalendarItemDto | 
try {
    val result : CalendarItemDto = apiInstance.modifyCalendarItem(calendarItemDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#modifyCalendarItem")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#modifyCalendarItem")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **calendarItemDto** | [**CalendarItemDto**](CalendarItemDto.md)|  |

### Return type

[**CalendarItemDto**](CalendarItemDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setCalendarItemsDelegations"></a>
# **setCalendarItemsDelegations**
> kotlin.collections.List&lt;CalendarItemDto&gt; setCalendarItemsDelegations(icureStubDto)

Update delegations in calendarItems

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val icureStubDto : kotlin.collections.List<IcureStubDto> =  // kotlin.collections.List<IcureStubDto> | 
try {
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.setCalendarItemsDelegations(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#setCalendarItemsDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#setCalendarItemsDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **icureStubDto** | [**kotlin.collections.List&lt;IcureStubDto&gt;**](IcureStubDto.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;CalendarItemDto&gt;**](CalendarItemDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

