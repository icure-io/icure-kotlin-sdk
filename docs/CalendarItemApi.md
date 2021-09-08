# CalendarItemApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createCalendarItem**](CalendarItemApi.md#createCalendarItem) | **POST** /rest/v2/calendarItem | Creates a calendarItem
[**createCalendarItem1**](CalendarItemApi.md#createCalendarItem1) | **POST** /rest/v1/calendarItem | Creates a calendarItem
[**deleteCalendarItem**](CalendarItemApi.md#deleteCalendarItem) | **DELETE** /rest/v1/calendarItem/{calendarItemIds} | Deletes an calendarItem
[**deleteCalendarItems**](CalendarItemApi.md#deleteCalendarItems) | **DELETE** /rest/v2/calendarItem/delete/batch | Deletes an calendarItem
[**findCalendarItemsByHCPartyPatientForeignKeys**](CalendarItemApi.md#findCalendarItemsByHCPartyPatientForeignKeys) | **GET** /rest/v2/calendarItem/byHcPartySecretForeignKeys | Find CalendarItems by hcparty and patient
[**findCalendarItemsByHCPartyPatientForeignKeys1**](CalendarItemApi.md#findCalendarItemsByHCPartyPatientForeignKeys1) | **GET** /rest/v1/calendarItem/byHcPartySecretForeignKeys | Find CalendarItems by hcparty and patient
[**getCalendarItem**](CalendarItemApi.md#getCalendarItem) | **GET** /rest/v2/calendarItem/{calendarItemId} | Gets an calendarItem
[**getCalendarItem1**](CalendarItemApi.md#getCalendarItem1) | **GET** /rest/v1/calendarItem/{calendarItemId} | Gets an calendarItem
[**getCalendarItems**](CalendarItemApi.md#getCalendarItems) | **GET** /rest/v2/calendarItem | Gets all calendarItems
[**getCalendarItems1**](CalendarItemApi.md#getCalendarItems1) | **GET** /rest/v1/calendarItem | Gets all calendarItems
[**getCalendarItemsByPeriodAndHcPartyId**](CalendarItemApi.md#getCalendarItemsByPeriodAndHcPartyId) | **POST** /rest/v2/calendarItem/byPeriodAndHcPartyId | Get CalendarItems by Period and HcPartyId
[**getCalendarItemsByPeriodAndHcPartyId1**](CalendarItemApi.md#getCalendarItemsByPeriodAndHcPartyId1) | **POST** /rest/v1/calendarItem/byPeriodAndHcPartyId | Get CalendarItems by Period and HcPartyId
[**getCalendarItemsWithIds**](CalendarItemApi.md#getCalendarItemsWithIds) | **POST** /rest/v2/calendarItem/byIds | Get calendarItems by ids
[**getCalendarItemsWithIds1**](CalendarItemApi.md#getCalendarItemsWithIds1) | **POST** /rest/v1/calendarItem/byIds | Get calendarItems by id
[**getCalendarsByPeriodAndAgendaId**](CalendarItemApi.md#getCalendarsByPeriodAndAgendaId) | **POST** /rest/v2/calendarItem/byPeriodAndAgendaId | Get CalendarItems by Period and AgendaId
[**getCalendarsByPeriodAndAgendaId1**](CalendarItemApi.md#getCalendarsByPeriodAndAgendaId1) | **POST** /rest/v1/calendarItem/byPeriodAndAgendaId | Get CalendarItems by Period and AgendaId
[**modifyCalendarItem**](CalendarItemApi.md#modifyCalendarItem) | **PUT** /rest/v2/calendarItem | Modifies an calendarItem
[**modifyCalendarItem1**](CalendarItemApi.md#modifyCalendarItem1) | **PUT** /rest/v1/calendarItem | Modifies an calendarItem
[**setCalendarItemsDelegations**](CalendarItemApi.md#setCalendarItemsDelegations) | **POST** /rest/v2/calendarItem/delegations | Update delegations in calendarItems
[**setCalendarItemsDelegations1**](CalendarItemApi.md#setCalendarItemsDelegations1) | **POST** /rest/v1/calendarItem/delegations | Update delegations in calendarItems


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

<a name="createCalendarItem1"></a>
# **createCalendarItem1**
> CalendarItemDto createCalendarItem1(calendarItemDto)

Creates a calendarItem

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val calendarItemDto : CalendarItemDto =  // CalendarItemDto | 
try {
    val result : CalendarItemDto = apiInstance.createCalendarItem1(calendarItemDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#createCalendarItem1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#createCalendarItem1")
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

<a name="deleteCalendarItems"></a>
# **deleteCalendarItems**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteCalendarItems(listOfIdsDto)

Deletes an calendarItem

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteCalendarItems(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#deleteCalendarItems")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#deleteCalendarItems")
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

<a name="findCalendarItemsByHCPartyPatientForeignKeys1"></a>
# **findCalendarItemsByHCPartyPatientForeignKeys1**
> kotlin.collections.List&lt;CalendarItemDto&gt; findCalendarItemsByHCPartyPatientForeignKeys1(hcPartyId, secretFKeys)

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
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.findCalendarItemsByHCPartyPatientForeignKeys1(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#findCalendarItemsByHCPartyPatientForeignKeys1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#findCalendarItemsByHCPartyPatientForeignKeys1")
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

<a name="getCalendarItem1"></a>
# **getCalendarItem1**
> CalendarItemDto getCalendarItem1(calendarItemId)

Gets an calendarItem

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val calendarItemId : kotlin.String = calendarItemId_example // kotlin.String | 
try {
    val result : CalendarItemDto = apiInstance.getCalendarItem1(calendarItemId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarItem1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarItem1")
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

<a name="getCalendarItems1"></a>
# **getCalendarItems1**
> kotlin.collections.List&lt;CalendarItemDto&gt; getCalendarItems1()

Gets all calendarItems

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
try {
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.getCalendarItems1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarItems1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarItems1")
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

<a name="getCalendarItemsByPeriodAndHcPartyId1"></a>
# **getCalendarItemsByPeriodAndHcPartyId1**
> kotlin.collections.List&lt;CalendarItemDto&gt; getCalendarItemsByPeriodAndHcPartyId1(startDate, endDate, hcPartyId)

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
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.getCalendarItemsByPeriodAndHcPartyId1(startDate, endDate, hcPartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarItemsByPeriodAndHcPartyId1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarItemsByPeriodAndHcPartyId1")
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

Get calendarItems by ids

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

<a name="getCalendarItemsWithIds1"></a>
# **getCalendarItemsWithIds1**
> kotlin.collections.List&lt;CalendarItemDto&gt; getCalendarItemsWithIds1(listOfIdsDto)

Get calendarItems by id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.getCalendarItemsWithIds1(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarItemsWithIds1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarItemsWithIds1")
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

<a name="getCalendarsByPeriodAndAgendaId1"></a>
# **getCalendarsByPeriodAndAgendaId1**
> kotlin.collections.List&lt;CalendarItemDto&gt; getCalendarsByPeriodAndAgendaId1(startDate, endDate, agendaId)

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
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.getCalendarsByPeriodAndAgendaId1(startDate, endDate, agendaId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#getCalendarsByPeriodAndAgendaId1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#getCalendarsByPeriodAndAgendaId1")
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

<a name="modifyCalendarItem1"></a>
# **modifyCalendarItem1**
> CalendarItemDto modifyCalendarItem1(calendarItemDto)

Modifies an calendarItem

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val calendarItemDto : CalendarItemDto =  // CalendarItemDto | 
try {
    val result : CalendarItemDto = apiInstance.modifyCalendarItem1(calendarItemDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#modifyCalendarItem1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#modifyCalendarItem1")
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

<a name="setCalendarItemsDelegations1"></a>
# **setCalendarItemsDelegations1**
> kotlin.collections.List&lt;CalendarItemDto&gt; setCalendarItemsDelegations1(icureStubDto)

Update delegations in calendarItems

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CalendarItemApi()
val icureStubDto : kotlin.collections.List<IcureStubDto> =  // kotlin.collections.List<IcureStubDto> | 
try {
    val result : kotlin.collections.List<CalendarItemDto> = apiInstance.setCalendarItemsDelegations1(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CalendarItemApi#setCalendarItemsDelegations1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CalendarItemApi#setCalendarItemsDelegations1")
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

