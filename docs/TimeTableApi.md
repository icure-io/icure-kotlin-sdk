# TimeTableApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createTimeTable**](TimeTableApi.md#createTimeTable) | **POST** /rest/v2/timeTable | Creates a timeTable
[**createTimeTable1**](TimeTableApi.md#createTimeTable1) | **POST** /rest/v1/timeTable | Creates a timeTable
[**deleteTimeTable**](TimeTableApi.md#deleteTimeTable) | **POST** /rest/v2/timeTable/delete/batch | Deletes an timeTable
[**deleteTimeTable1**](TimeTableApi.md#deleteTimeTable1) | **DELETE** /rest/v1/timeTable/{timeTableIds} | Deletes an timeTable
[**getTimeTable**](TimeTableApi.md#getTimeTable) | **GET** /rest/v2/timeTable/{timeTableId} | Gets a timeTable
[**getTimeTable1**](TimeTableApi.md#getTimeTable1) | **GET** /rest/v1/timeTable/{timeTableId} | Gets a timeTable
[**getTimeTablesByAgendaId**](TimeTableApi.md#getTimeTablesByAgendaId) | **POST** /rest/v2/timeTable/byAgendaId | Get TimeTables by AgendaId
[**getTimeTablesByAgendaId1**](TimeTableApi.md#getTimeTablesByAgendaId1) | **POST** /rest/v1/timeTable/byAgendaId | Get TimeTables by AgendaId
[**getTimeTablesByPeriodAndAgendaId**](TimeTableApi.md#getTimeTablesByPeriodAndAgendaId) | **POST** /rest/v2/timeTable/byPeriodAndAgendaId | Get TimeTables by Period and AgendaId
[**getTimeTablesByPeriodAndAgendaId1**](TimeTableApi.md#getTimeTablesByPeriodAndAgendaId1) | **POST** /rest/v1/timeTable/byPeriodAndAgendaId | Get TimeTables by Period and AgendaId
[**modifyTimeTable**](TimeTableApi.md#modifyTimeTable) | **PUT** /rest/v2/timeTable | Modifies an timeTable
[**modifyTimeTable1**](TimeTableApi.md#modifyTimeTable1) | **PUT** /rest/v1/timeTable | Modifies an timeTable


<a name="createTimeTable"></a>
# **createTimeTable**
> TimeTableDto createTimeTable(timeTableDto)

Creates a timeTable

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val timeTableDto : TimeTableDto =  // TimeTableDto | 
try {
    val result : TimeTableDto = apiInstance.createTimeTable(timeTableDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#createTimeTable")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#createTimeTable")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **timeTableDto** | [**TimeTableDto**](TimeTableDto.md)|  |

### Return type

[**TimeTableDto**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTimeTable1"></a>
# **createTimeTable1**
> TimeTableDto createTimeTable1(timeTableDto)

Creates a timeTable

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val timeTableDto : TimeTableDto =  // TimeTableDto | 
try {
    val result : TimeTableDto = apiInstance.createTimeTable1(timeTableDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#createTimeTable1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#createTimeTable1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **timeTableDto** | [**TimeTableDto**](TimeTableDto.md)|  |

### Return type

[**TimeTableDto**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteTimeTable"></a>
# **deleteTimeTable**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteTimeTable(listOfIdsDto)

Deletes an timeTable

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteTimeTable(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#deleteTimeTable")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#deleteTimeTable")
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

<a name="deleteTimeTable1"></a>
# **deleteTimeTable1**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteTimeTable1(timeTableIds)

Deletes an timeTable

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val timeTableIds : kotlin.String = timeTableIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteTimeTable1(timeTableIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#deleteTimeTable1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#deleteTimeTable1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **timeTableIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTimeTable"></a>
# **getTimeTable**
> TimeTableDto getTimeTable(timeTableId)

Gets a timeTable

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val timeTableId : kotlin.String = timeTableId_example // kotlin.String | 
try {
    val result : TimeTableDto = apiInstance.getTimeTable(timeTableId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#getTimeTable")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#getTimeTable")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **timeTableId** | **kotlin.String**|  |

### Return type

[**TimeTableDto**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTimeTable1"></a>
# **getTimeTable1**
> TimeTableDto getTimeTable1(timeTableId)

Gets a timeTable

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val timeTableId : kotlin.String = timeTableId_example // kotlin.String | 
try {
    val result : TimeTableDto = apiInstance.getTimeTable1(timeTableId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#getTimeTable1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#getTimeTable1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **timeTableId** | **kotlin.String**|  |

### Return type

[**TimeTableDto**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTimeTablesByAgendaId"></a>
# **getTimeTablesByAgendaId**
> kotlin.collections.List&lt;TimeTableDto&gt; getTimeTablesByAgendaId(agendaId)

Get TimeTables by AgendaId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val agendaId : kotlin.String = agendaId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<TimeTableDto> = apiInstance.getTimeTablesByAgendaId(agendaId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#getTimeTablesByAgendaId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#getTimeTablesByAgendaId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **agendaId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;TimeTableDto&gt;**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTimeTablesByAgendaId1"></a>
# **getTimeTablesByAgendaId1**
> kotlin.collections.List&lt;TimeTableDto&gt; getTimeTablesByAgendaId1(agendaId)

Get TimeTables by AgendaId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val agendaId : kotlin.String = agendaId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<TimeTableDto> = apiInstance.getTimeTablesByAgendaId1(agendaId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#getTimeTablesByAgendaId1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#getTimeTablesByAgendaId1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **agendaId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;TimeTableDto&gt;**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTimeTablesByPeriodAndAgendaId"></a>
# **getTimeTablesByPeriodAndAgendaId**
> kotlin.collections.List&lt;TimeTableDto&gt; getTimeTablesByPeriodAndAgendaId(startDate, endDate, agendaId)

Get TimeTables by Period and AgendaId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val startDate : kotlin.Long = 789 // kotlin.Long | 
val endDate : kotlin.Long = 789 // kotlin.Long | 
val agendaId : kotlin.String = agendaId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<TimeTableDto> = apiInstance.getTimeTablesByPeriodAndAgendaId(startDate, endDate, agendaId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#getTimeTablesByPeriodAndAgendaId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#getTimeTablesByPeriodAndAgendaId")
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

[**kotlin.collections.List&lt;TimeTableDto&gt;**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTimeTablesByPeriodAndAgendaId1"></a>
# **getTimeTablesByPeriodAndAgendaId1**
> kotlin.collections.List&lt;TimeTableDto&gt; getTimeTablesByPeriodAndAgendaId1(startDate, endDate, agendaId)

Get TimeTables by Period and AgendaId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val startDate : kotlin.Long = 789 // kotlin.Long | 
val endDate : kotlin.Long = 789 // kotlin.Long | 
val agendaId : kotlin.String = agendaId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<TimeTableDto> = apiInstance.getTimeTablesByPeriodAndAgendaId1(startDate, endDate, agendaId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#getTimeTablesByPeriodAndAgendaId1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#getTimeTablesByPeriodAndAgendaId1")
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

[**kotlin.collections.List&lt;TimeTableDto&gt;**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyTimeTable"></a>
# **modifyTimeTable**
> TimeTableDto modifyTimeTable(timeTableDto)

Modifies an timeTable

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val timeTableDto : TimeTableDto =  // TimeTableDto | 
try {
    val result : TimeTableDto = apiInstance.modifyTimeTable(timeTableDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#modifyTimeTable")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#modifyTimeTable")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **timeTableDto** | [**TimeTableDto**](TimeTableDto.md)|  |

### Return type

[**TimeTableDto**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTimeTable1"></a>
# **modifyTimeTable1**
> TimeTableDto modifyTimeTable1(timeTableDto)

Modifies an timeTable

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TimeTableApi()
val timeTableDto : TimeTableDto =  // TimeTableDto | 
try {
    val result : TimeTableDto = apiInstance.modifyTimeTable1(timeTableDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TimeTableApi#modifyTimeTable1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TimeTableApi#modifyTimeTable1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **timeTableDto** | [**TimeTableDto**](TimeTableDto.md)|  |

### Return type

[**TimeTableDto**](TimeTableDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

