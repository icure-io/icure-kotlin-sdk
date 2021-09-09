# InsuranceApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createInsurance**](InsuranceApi.md#createInsurance) | **POST** /rest/v1/insurance | Creates an insurance
[**deleteInsurance**](InsuranceApi.md#deleteInsurance) | **DELETE** /rest/v1/insurance/{insuranceId} | Deletes an insurance
[**getInsurance**](InsuranceApi.md#getInsurance) | **GET** /rest/v1/insurance/{insuranceId} | Gets an insurance
[**getInsurances**](InsuranceApi.md#getInsurances) | **POST** /rest/v1/insurance/byIds | Gets insurances by id
[**listInsurancesByCode**](InsuranceApi.md#listInsurancesByCode) | **GET** /rest/v1/insurance/byCode/{insuranceCode} | Gets an insurance
[**listInsurancesByName**](InsuranceApi.md#listInsurancesByName) | **GET** /rest/v1/insurance/byName/{insuranceName} | Gets an insurance
[**modifyInsurance**](InsuranceApi.md#modifyInsurance) | **PUT** /rest/v1/insurance | Modifies an insurance


<a name="createInsurance"></a>
# **createInsurance**
> InsuranceDto createInsurance(insuranceDto)

Creates an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceDto : InsuranceDto =  // InsuranceDto | 
try {
    val result : InsuranceDto = apiInstance.createInsurance(insuranceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#createInsurance")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#createInsurance")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **insuranceDto** | [**InsuranceDto**](InsuranceDto.md)|  |

### Return type

[**InsuranceDto**](InsuranceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteInsurance"></a>
# **deleteInsurance**
> DocIdentifier deleteInsurance(insuranceId)

Deletes an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceId : kotlin.String = insuranceId_example // kotlin.String | 
try {
    val result : DocIdentifier = apiInstance.deleteInsurance(insuranceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#deleteInsurance")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#deleteInsurance")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **insuranceId** | **kotlin.String**|  |

### Return type

[**DocIdentifier**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getInsurance"></a>
# **getInsurance**
> InsuranceDto getInsurance(insuranceId)

Gets an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceId : kotlin.String = insuranceId_example // kotlin.String | 
try {
    val result : InsuranceDto = apiInstance.getInsurance(insuranceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#getInsurance")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#getInsurance")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **insuranceId** | **kotlin.String**|  |

### Return type

[**InsuranceDto**](InsuranceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getInsurances"></a>
# **getInsurances**
> kotlin.collections.List&lt;InsuranceDto&gt; getInsurances(listOfIdsDto)

Gets insurances by id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<InsuranceDto> = apiInstance.getInsurances(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#getInsurances")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#getInsurances")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;InsuranceDto&gt;**](InsuranceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listInsurancesByCode"></a>
# **listInsurancesByCode**
> kotlin.collections.List&lt;InsuranceDto&gt; listInsurancesByCode(insuranceCode)

Gets an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceCode : kotlin.String = insuranceCode_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InsuranceDto> = apiInstance.listInsurancesByCode(insuranceCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#listInsurancesByCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#listInsurancesByCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **insuranceCode** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;InsuranceDto&gt;**](InsuranceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listInsurancesByName"></a>
# **listInsurancesByName**
> kotlin.collections.List&lt;InsuranceDto&gt; listInsurancesByName(insuranceName)

Gets an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceName : kotlin.String = insuranceName_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InsuranceDto> = apiInstance.listInsurancesByName(insuranceName)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#listInsurancesByName")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#listInsurancesByName")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **insuranceName** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;InsuranceDto&gt;**](InsuranceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyInsurance"></a>
# **modifyInsurance**
> InsuranceDto modifyInsurance(insuranceDto)

Modifies an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceDto : InsuranceDto =  // InsuranceDto | 
try {
    val result : InsuranceDto = apiInstance.modifyInsurance(insuranceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#modifyInsurance")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#modifyInsurance")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **insuranceDto** | [**InsuranceDto**](InsuranceDto.md)|  |

### Return type

[**InsuranceDto**](InsuranceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

