# MedicalLocationApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createMedicalLocation**](MedicalLocationApi.md#createMedicalLocation) | **POST** /rest/v2/medicallocation | Creates a medical location
[**deleteMedicalLocations**](MedicalLocationApi.md#deleteMedicalLocations) | **POST** /rest/v2/medicallocation/delete/batch | Deletes medical locations
[**getMedicalLocation**](MedicalLocationApi.md#getMedicalLocation) | **GET** /rest/v2/medicallocation/{locationId} | Gets a medical location
[**getMedicalLocations**](MedicalLocationApi.md#getMedicalLocations) | **GET** /rest/v2/medicallocation | Gets all medical locations
[**modifyMedicalLocation**](MedicalLocationApi.md#modifyMedicalLocation) | **PUT** /rest/v2/medicallocation | Modifies a medical location


<a name="createMedicalLocation"></a>
# **createMedicalLocation**
> MedicalLocationDto createMedicalLocation(medicalLocationDto)

Creates a medical location

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicalLocationApi()
val medicalLocationDto : MedicalLocationDto =  // MedicalLocationDto | 
try {
    val result : MedicalLocationDto = apiInstance.createMedicalLocation(medicalLocationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicalLocationApi#createMedicalLocation")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicalLocationApi#createMedicalLocation")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **medicalLocationDto** | [**MedicalLocationDto**](MedicalLocationDto.md)|  |

### Return type

[**MedicalLocationDto**](MedicalLocationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteMedicalLocations"></a>
# **deleteMedicalLocations**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteMedicalLocations(listOfIdsDto)

Deletes medical locations

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicalLocationApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteMedicalLocations(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicalLocationApi#deleteMedicalLocations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicalLocationApi#deleteMedicalLocations")
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

<a name="getMedicalLocation"></a>
# **getMedicalLocation**
> MedicalLocationDto getMedicalLocation(locationId)

Gets a medical location

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicalLocationApi()
val locationId : kotlin.String = locationId_example // kotlin.String | 
try {
    val result : MedicalLocationDto = apiInstance.getMedicalLocation(locationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicalLocationApi#getMedicalLocation")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicalLocationApi#getMedicalLocation")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **locationId** | **kotlin.String**|  |

### Return type

[**MedicalLocationDto**](MedicalLocationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getMedicalLocations"></a>
# **getMedicalLocations**
> kotlin.collections.List&lt;MedicalLocationDto&gt; getMedicalLocations()

Gets all medical locations

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicalLocationApi()
try {
    val result : kotlin.collections.List<MedicalLocationDto> = apiInstance.getMedicalLocations()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicalLocationApi#getMedicalLocations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicalLocationApi#getMedicalLocations")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;MedicalLocationDto&gt;**](MedicalLocationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyMedicalLocation"></a>
# **modifyMedicalLocation**
> MedicalLocationDto modifyMedicalLocation(medicalLocationDto)

Modifies a medical location

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicalLocationApi()
val medicalLocationDto : MedicalLocationDto =  // MedicalLocationDto | 
try {
    val result : MedicalLocationDto = apiInstance.modifyMedicalLocation(medicalLocationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicalLocationApi#modifyMedicalLocation")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicalLocationApi#modifyMedicalLocation")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **medicalLocationDto** | [**MedicalLocationDto**](MedicalLocationDto.md)|  |

### Return type

[**MedicalLocationDto**](MedicalLocationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

