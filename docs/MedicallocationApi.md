# MedicallocationApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createMedicalLocation**](MedicallocationApi.md#createMedicalLocation) | **POST** /rest/v2/medicallocation | Creates a medical location
[**createMedicalLocation1**](MedicallocationApi.md#createMedicalLocation1) | **POST** /rest/v1/medicallocation | Creates a medical location
[**deleteMedicalLocation**](MedicallocationApi.md#deleteMedicalLocation) | **DELETE** /rest/v1/medicallocation/{locationIds} | Deletes a medical location
[**deleteMedicalLocations**](MedicallocationApi.md#deleteMedicalLocations) | **DELETE** /rest/v2/medicallocation/delete/batch | Deletes medical locations
[**getMedicalLocation**](MedicallocationApi.md#getMedicalLocation) | **GET** /rest/v2/medicallocation/{locationId} | Gets a medical location
[**getMedicalLocation1**](MedicallocationApi.md#getMedicalLocation1) | **GET** /rest/v1/medicallocation/{locationId} | Gets a medical location
[**getMedicalLocations**](MedicallocationApi.md#getMedicalLocations) | **GET** /rest/v2/medicallocation | Gets all medical locations
[**getMedicalLocations1**](MedicallocationApi.md#getMedicalLocations1) | **GET** /rest/v1/medicallocation | Gets all medical locations
[**modifyMedicalLocation**](MedicallocationApi.md#modifyMedicalLocation) | **PUT** /rest/v2/medicallocation | Modifies a medical location
[**modifyMedicalLocation1**](MedicallocationApi.md#modifyMedicalLocation1) | **PUT** /rest/v1/medicallocation | Modifies a medical location


<a name="createMedicalLocation"></a>
# **createMedicalLocation**
> MedicalLocationDto createMedicalLocation(medicalLocationDto)

Creates a medical location

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicallocationApi()
val medicalLocationDto : MedicalLocationDto =  // MedicalLocationDto | 
try {
    val result : MedicalLocationDto = apiInstance.createMedicalLocation(medicalLocationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#createMedicalLocation")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#createMedicalLocation")
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

<a name="createMedicalLocation1"></a>
# **createMedicalLocation1**
> MedicalLocationDto createMedicalLocation1(medicalLocationDto)

Creates a medical location

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicallocationApi()
val medicalLocationDto : MedicalLocationDto =  // MedicalLocationDto | 
try {
    val result : MedicalLocationDto = apiInstance.createMedicalLocation1(medicalLocationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#createMedicalLocation1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#createMedicalLocation1")
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

<a name="deleteMedicalLocation"></a>
# **deleteMedicalLocation**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteMedicalLocation(locationIds)

Deletes a medical location

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicallocationApi()
val locationIds : kotlin.String = locationIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteMedicalLocation(locationIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#deleteMedicalLocation")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#deleteMedicalLocation")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **locationIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
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

val apiInstance = MedicallocationApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteMedicalLocations(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#deleteMedicalLocations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#deleteMedicalLocations")
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

val apiInstance = MedicallocationApi()
val locationId : kotlin.String = locationId_example // kotlin.String | 
try {
    val result : MedicalLocationDto = apiInstance.getMedicalLocation(locationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#getMedicalLocation")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#getMedicalLocation")
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

<a name="getMedicalLocation1"></a>
# **getMedicalLocation1**
> MedicalLocationDto getMedicalLocation1(locationId)

Gets a medical location

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicallocationApi()
val locationId : kotlin.String = locationId_example // kotlin.String | 
try {
    val result : MedicalLocationDto = apiInstance.getMedicalLocation1(locationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#getMedicalLocation1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#getMedicalLocation1")
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

val apiInstance = MedicallocationApi()
try {
    val result : kotlin.collections.List<MedicalLocationDto> = apiInstance.getMedicalLocations()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#getMedicalLocations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#getMedicalLocations")
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

<a name="getMedicalLocations1"></a>
# **getMedicalLocations1**
> kotlin.collections.List&lt;MedicalLocationDto&gt; getMedicalLocations1()

Gets all medical locations

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicallocationApi()
try {
    val result : kotlin.collections.List<MedicalLocationDto> = apiInstance.getMedicalLocations1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#getMedicalLocations1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#getMedicalLocations1")
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

val apiInstance = MedicallocationApi()
val medicalLocationDto : MedicalLocationDto =  // MedicalLocationDto | 
try {
    val result : MedicalLocationDto = apiInstance.modifyMedicalLocation(medicalLocationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#modifyMedicalLocation")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#modifyMedicalLocation")
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

<a name="modifyMedicalLocation1"></a>
# **modifyMedicalLocation1**
> MedicalLocationDto modifyMedicalLocation1(medicalLocationDto)

Modifies a medical location

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedicallocationApi()
val medicalLocationDto : MedicalLocationDto =  // MedicalLocationDto | 
try {
    val result : MedicalLocationDto = apiInstance.modifyMedicalLocation1(medicalLocationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedicallocationApi#modifyMedicalLocation1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedicallocationApi#modifyMedicalLocation1")
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

