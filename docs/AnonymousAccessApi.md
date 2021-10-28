# AnonymousAccessApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**listHealthcarePartiesInGroup**](AnonymousAccessApi.md#listHealthcarePartiesInGroup) | **GET** /rest/v1/aa/hcparty/inGroup/{groupId} | List healthcare parties for a provided group id


<a name="listHealthcarePartiesInGroup"></a>
# **listHealthcarePartiesInGroup**
> kotlin.collections.List&lt;HealthcarePartyDto&gt; listHealthcarePartiesInGroup(groupId)

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
    val result : kotlin.collections.List<HealthcarePartyDto> = apiInstance.listHealthcarePartiesInGroup(groupId)
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

[**kotlin.collections.List&lt;HealthcarePartyDto&gt;**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

