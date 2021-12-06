# AnonymousAccessApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**getAvailabilitiesByPeriodAndCalendarItemTypeId**](AnonymousAccessApi.md#getAvailabilitiesByPeriodAndCalendarItemTypeId) | **GET** /rest/v2/aa/available/inGroup/{groupId}/forUser/{userId}/type/{getCalendarItemTypeId} | Get Availabilities for HCP and appointmentType
[**listAppointmentTypesForUser**](AnonymousAccessApi.md#listAppointmentTypesForUser) | **GET** /rest/v2/aa/appointmentType/inGroup/{groupId}/forUser/{userId} | List Calendar Item types for a provided group id and user id
[**listHealthcarePartiesInGroup**](AnonymousAccessApi.md#listHealthcarePartiesInGroup) | **GET** /rest/v2/aa/hcparty/inGroup/{groupId} | List healthcare parties for a provided group id


<a name="getAvailabilitiesByPeriodAndCalendarItemTypeId"></a>
# **getAvailabilitiesByPeriodAndCalendarItemTypeId**
> kotlin.collections.List&lt;kotlin.Long&gt; getAvailabilitiesByPeriodAndCalendarItemTypeId(groupId, userId, getCalendarItemTypeId, startDate, endDate, hcpId, limit)

Get Availabilities for HCP and appointmentType

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AnonymousAccessApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val userId : kotlin.String = userId_example // kotlin.String | 
val getCalendarItemTypeId : kotlin.String = getCalendarItemTypeId_example // kotlin.String | 
val startDate : kotlin.Long = 789 // kotlin.Long | 
val endDate : kotlin.Long = 789 // kotlin.Long | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<kotlin.Long> = apiInstance.getAvailabilitiesByPeriodAndCalendarItemTypeId(groupId, userId, getCalendarItemTypeId, startDate, endDate, hcpId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AnonymousAccessApi#getAvailabilitiesByPeriodAndCalendarItemTypeId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AnonymousAccessApi#getAvailabilitiesByPeriodAndCalendarItemTypeId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **userId** | **kotlin.String**|  |
 **getCalendarItemTypeId** | **kotlin.String**|  |
 **startDate** | **kotlin.Long**|  |
 **endDate** | **kotlin.Long**|  |
 **hcpId** | **kotlin.String**|  |
 **limit** | **kotlin.Int**|  | [optional]

### Return type

**kotlin.collections.List&lt;kotlin.Long&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listAppointmentTypesForUser"></a>
# **listAppointmentTypesForUser**
> kotlin.collections.List&lt;CalendarItemTypeDto&gt; listAppointmentTypesForUser(groupId, userId, startDate, endDate)

List Calendar Item types for a provided group id and user id

Returns a list of Calendar Item types

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AnonymousAccessApi()
val groupId : kotlin.String = groupId_example // kotlin.String | Healthcare parties group id
val userId : kotlin.String = userId_example // kotlin.String | Healthcare party user id
val startDate : kotlin.Long = 789 // kotlin.Long | 
val endDate : kotlin.Long = 789 // kotlin.Long | 
try {
    val result : kotlin.collections.List<CalendarItemTypeDto> = apiInstance.listAppointmentTypesForUser(groupId, userId, startDate, endDate)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AnonymousAccessApi#listAppointmentTypesForUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AnonymousAccessApi#listAppointmentTypesForUser")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**| Healthcare parties group id |
 **userId** | **kotlin.String**| Healthcare party user id |
 **startDate** | **kotlin.Long**|  |
 **endDate** | **kotlin.Long**|  |

### Return type

[**kotlin.collections.List&lt;CalendarItemTypeDto&gt;**](CalendarItemTypeDto.md)

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

