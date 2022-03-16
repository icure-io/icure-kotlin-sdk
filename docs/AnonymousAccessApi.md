# AnonymousAccessApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**
getAvailabilitiesByPeriodAndCalendarItemTypeId**](AnonymousAccessApi.md#getAvailabilitiesByPeriodAndCalendarItemTypeId) | **
GET** /rest/v2/aa/available/inGroup/{groupId}/forUser/{userId}/type/{calendarItemTypeId} | Get Availabilities for HCP and appointmentType
[**listAppointmentTypesForUser**](AnonymousAccessApi.md#listAppointmentTypesForUser) | **
GET** /rest/v2/aa/appointmentType/inGroup/{groupId}/forUser/{userId} | List Calendar Item types for a provided group id and user id
[**listHealthcarePartiesInGroup**](AnonymousAccessApi.md#listHealthcarePartiesInGroup) | **GET** /rest/v2/aa/hcparty/inGroup/{groupId} | List healthcare parties for a provided group id


<a name="getAvailabilitiesByPeriodAndCalendarItemTypeId"></a>
# **getAvailabilitiesByPeriodAndCalendarItemTypeId**

> kotlin.collections.List&lt;kotlin.Long&gt; getAvailabilitiesByPeriodAndCalendarItemTypeId(groupId, userId, calendarItemTypeId, isNewPatient, startDate, endDate, hcpId, placeId, limit)

Get Availabilities for HCP and appointmentType

The start of the slot is returned in YYYYDDMMHHmmss format and only slots belonging to public time tables are returned.

### Example

```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AnonymousAccessApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val userId : kotlin.String = userId_example // kotlin.String | 
val calendarItemTypeId : kotlin.String = calendarItemTypeId_example // kotlin.String | 
val isNewPatient : kotlin.Boolean = true // kotlin.Boolean | 
val startDate : kotlin.Long = 789 // kotlin.Long | 
val endDate : kotlin.Long = 789 // kotlin.Long | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
val placeId : kotlin.String = placeId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<kotlin.Long> = apiInstance.getAvailabilitiesByPeriodAndCalendarItemTypeId(groupId, userId, calendarItemTypeId, isNewPatient, startDate, endDate, hcpId, placeId, limit)
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
**calendarItemTypeId** | **kotlin.String**|  |
**isNewPatient** | **kotlin.Boolean**|  |
**startDate** | **kotlin.Long**|  |
**endDate** | **kotlin.Long**|  |
**hcpId** | **kotlin.String**|  |
**placeId** | **kotlin.String**|  | [optional]
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

> kotlin.collections.List&lt;AppointmentTypeAndPlaceDto&gt; listAppointmentTypesForUser(groupId, userId, startDate, endDate)

List Calendar Item types for a provided group id and user id

Returns a list of Calendar Item types. In order to be returned, the Calendar Item Type must be linked to a time table enclosed in an Agenda for which an anonymous right has been set (a Right with read permission and null user)

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
    val result : kotlin.collections.List<AppointmentTypeAndPlaceDto> = apiInstance.listAppointmentTypesForUser(groupId, userId, startDate, endDate)
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

[**kotlin.collections.List&lt;AppointmentTypeAndPlaceDto&gt;**](AppointmentTypeAndPlaceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listHealthcarePartiesInGroup"></a>
# **listHealthcarePartiesInGroup**

> kotlin.collections.List&lt;UserAndHealthcarePartyDto&gt; listHealthcarePartiesInGroup(groupId)

List healthcare parties for a provided group id

Returns a list of Users/healthcare parties contained in the group owning the providing id. In order to be returned, a healthcare party needs to be linked to a user an this user must have a property &#39;org.taktik.icure.public&#39; set to a boolean true.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AnonymousAccessApi()
val groupId : kotlin.String = groupId_example // kotlin.String | Healthcare parties group id
try {
    val result : kotlin.collections.List<UserAndHealthcarePartyDto> = apiInstance.listHealthcarePartiesInGroup(groupId)
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

[**kotlin.collections.List&lt;UserAndHealthcarePartyDto&gt;**](UserAndHealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

