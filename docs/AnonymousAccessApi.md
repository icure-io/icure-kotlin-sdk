# AnonymousAccessApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**getAvailabilitiesByPeriodAndAgendaId**](AnonymousAccessApi.md#getAvailabilitiesByPeriodAndAgendaId) | **GET** /rest/v2/aa/available/inGroup/{groupId}/agenda/{agendaId} | Get Availabilities for HCP and agendaId
[**listAgendasInHealthcareParty**](AnonymousAccessApi.md#listAgendasInHealthcareParty) | **GET** /rest/v2/aa/agenda/inGroup/{groupId}/forUser/{userId} | List healthcare parties for a provided group id
[**listHealthcarePartiesInGroup**](AnonymousAccessApi.md#listHealthcarePartiesInGroup) | **GET** /rest/v2/aa/hcparty/inGroup/{groupId} | List healthcare parties for a provided group id


<a name="getAvailabilitiesByPeriodAndAgendaId"></a>
# **getAvailabilitiesByPeriodAndAgendaId**
> kotlin.collections.List&lt;kotlin.Long&gt; getAvailabilitiesByPeriodAndAgendaId(groupId, agendaId, startDate, endDate, hcpId, duration, limit)

Get Availabilities for HCP and agendaId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AnonymousAccessApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val agendaId : kotlin.String = agendaId_example // kotlin.String | 
val startDate : kotlin.Long = 789 // kotlin.Long | 
val endDate : kotlin.Long = 789 // kotlin.Long | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
val duration : kotlin.Long = 789 // kotlin.Long | 
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<kotlin.Long> = apiInstance.getAvailabilitiesByPeriodAndAgendaId(groupId, agendaId, startDate, endDate, hcpId, duration, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AnonymousAccessApi#getAvailabilitiesByPeriodAndAgendaId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AnonymousAccessApi#getAvailabilitiesByPeriodAndAgendaId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **agendaId** | **kotlin.String**|  |
 **startDate** | **kotlin.Long**|  |
 **endDate** | **kotlin.Long**|  |
 **hcpId** | **kotlin.String**|  |
 **duration** | **kotlin.Long**|  |
 **limit** | **kotlin.Int**|  | [optional]

### Return type

**kotlin.collections.List&lt;kotlin.Long&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listAgendasInHealthcareParty"></a>
# **listAgendasInHealthcareParty**
> kotlin.collections.List&lt;AgendaDto&gt; listAgendasInHealthcareParty(groupId, userId)

List healthcare parties for a provided group id

Returns a list of healthcare parties contained in the group owning the providing id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AnonymousAccessApi()
val groupId : kotlin.String = groupId_example // kotlin.String | Healthcare parties group id
val userId : kotlin.String = userId_example // kotlin.String | Healthcare party user id
try {
    val result : kotlin.collections.List<AgendaDto> = apiInstance.listAgendasInHealthcareParty(groupId, userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AnonymousAccessApi#listAgendasInHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AnonymousAccessApi#listAgendasInHealthcareParty")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**| Healthcare parties group id |
 **userId** | **kotlin.String**| Healthcare party user id |

### Return type

[**kotlin.collections.List&lt;AgendaDto&gt;**](AgendaDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listHealthcarePartiesInGroup"></a>
# **listHealthcarePartiesInGroup**
> kotlin.collections.List&lt;UserDto&gt; listHealthcarePartiesInGroup(groupId)

List healthcare parties for a provided group id

Returns a list of healthcare parties contained in the group owning the providing id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AnonymousAccessApi()
val groupId : kotlin.String = groupId_example // kotlin.String | Healthcare parties group id
try {
    val result : kotlin.collections.List<UserDto> = apiInstance.listHealthcarePartiesInGroup(groupId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AnonymousAccessApi#listHealthcarePartiesInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AnonymousAccessApi#listHealthcarePartiesInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**| Healthcare parties group id |

### Return type

[**kotlin.collections.List&lt;UserDto&gt;**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

