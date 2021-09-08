# MedexApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**generateMedex**](MedexApi.md#generateMedex) | **POST** /rest/v2/medex/generate | Generate a Medex XML String
[**generateMedex1**](MedexApi.md#generateMedex1) | **POST** /rest/v1/medex/generate | Generate a Medex XML String


<a name="generateMedex"></a>
# **generateMedex**
> kotlin.String generateMedex(medexInfoDto)

Generate a Medex XML String

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedexApi()
val medexInfoDto : MedexInfoDto =  // MedexInfoDto | 
try {
    val result : kotlin.String = apiInstance.generateMedex(medexInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedexApi#generateMedex")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedexApi#generateMedex")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **medexInfoDto** | [**MedexInfoDto**](MedexInfoDto.md)|  |

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/xml

<a name="generateMedex1"></a>
# **generateMedex1**
> kotlin.String generateMedex1(medexInfoDto)

Generate a Medex XML String

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MedexApi()
val medexInfoDto : MedexInfoDto =  // MedexInfoDto | 
try {
    val result : kotlin.String = apiInstance.generateMedex1(medexInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MedexApi#generateMedex1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MedexApi#generateMedex1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **medexInfoDto** | [**MedexInfoDto**](MedexInfoDto.md)|  |

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/xml

