# BeefactApi

All URIs are relative to *https://kraken.svc.icure.cloud*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createBatchAndMessage**](BeefactApi.md#createBatchAndMessage) | **POST** /rest/v2/be_efact/{insuranceId}/{newMessageId}/{numericalRef} | create batch and message


<a name="createBatchAndMessage"></a>
# **createBatchAndMessage**
> MessageWithBatch createBatchAndMessage(insuranceId, newMessageId, numericalRef, mapOfIdsDto)

create batch and message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BeefactApi()
val insuranceId : kotlin.String = insuranceId_example // kotlin.String | 
val newMessageId : kotlin.String = newMessageId_example // kotlin.String | 
val numericalRef : kotlin.Long = 789 // kotlin.Long | 
val mapOfIdsDto : MapOfIdsDto =  // MapOfIdsDto | 
try {
    val result : MessageWithBatch = apiInstance.createBatchAndMessage(insuranceId, newMessageId, numericalRef, mapOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BeefactApi#createBatchAndMessage")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BeefactApi#createBatchAndMessage")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **insuranceId** | **kotlin.String**|  |
 **newMessageId** | **kotlin.String**|  |
 **numericalRef** | **kotlin.Long**|  |
 **mapOfIdsDto** | [**MapOfIdsDto**](MapOfIdsDto.md)|  |

### Return type

[**MessageWithBatch**](MessageWithBatch.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

