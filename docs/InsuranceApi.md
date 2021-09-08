# InsuranceApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createInsurance**](InsuranceApi.md#createInsurance) | **POST** /rest/v2/insurance | Creates an insurance
[**createInsurance1**](InsuranceApi.md#createInsurance1) | **POST** /rest/v1/insurance | Creates an insurance
[**deleteInsurance**](InsuranceApi.md#deleteInsurance) | **DELETE** /rest/v2/insurance/{insuranceId} | Deletes an insurance
[**deleteInsurance1**](InsuranceApi.md#deleteInsurance1) | **DELETE** /rest/v1/insurance/{insuranceId} | Deletes an insurance
[**getInsurance**](InsuranceApi.md#getInsurance) | **GET** /rest/v2/insurance/{insuranceId} | Gets an insurance
[**getInsurance1**](InsuranceApi.md#getInsurance1) | **GET** /rest/v1/insurance/{insuranceId} | Gets an insurance
[**getInsurances**](InsuranceApi.md#getInsurances) | **POST** /rest/v2/insurance/byIds | Gets insurances by id
[**getInsurances1**](InsuranceApi.md#getInsurances1) | **POST** /rest/v1/insurance/byIds | Gets insurances by id
[**listInsurancesByCode**](InsuranceApi.md#listInsurancesByCode) | **GET** /rest/v2/insurance/byCode/{insuranceCode} | Gets an insurance
[**listInsurancesByCode1**](InsuranceApi.md#listInsurancesByCode1) | **GET** /rest/v1/insurance/byCode/{insuranceCode} | Gets an insurance
[**listInsurancesByName**](InsuranceApi.md#listInsurancesByName) | **GET** /rest/v2/insurance/byName/{insuranceName} | Gets an insurance
[**listInsurancesByName1**](InsuranceApi.md#listInsurancesByName1) | **GET** /rest/v1/insurance/byName/{insuranceName} | Gets an insurance
[**modifyInsurance**](InsuranceApi.md#modifyInsurance) | **PUT** /rest/v2/insurance | Modifies an insurance
[**modifyInsurance1**](InsuranceApi.md#modifyInsurance1) | **PUT** /rest/v1/insurance | Modifies an insurance


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

<a name="createInsurance1"></a>
# **createInsurance1**
> InsuranceDto createInsurance1(insuranceDto)

Creates an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceDto : InsuranceDto =  // InsuranceDto | 
try {
    val result : InsuranceDto = apiInstance.createInsurance1(insuranceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#createInsurance1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#createInsurance1")
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

<a name="deleteInsurance1"></a>
# **deleteInsurance1**
> DocIdentifier deleteInsurance1(insuranceId)

Deletes an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceId : kotlin.String = insuranceId_example // kotlin.String | 
try {
    val result : DocIdentifier = apiInstance.deleteInsurance1(insuranceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#deleteInsurance1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#deleteInsurance1")
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

<a name="getInsurance1"></a>
# **getInsurance1**
> InsuranceDto getInsurance1(insuranceId)

Gets an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceId : kotlin.String = insuranceId_example // kotlin.String | 
try {
    val result : InsuranceDto = apiInstance.getInsurance1(insuranceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#getInsurance1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#getInsurance1")
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

<a name="getInsurances1"></a>
# **getInsurances1**
> kotlin.collections.List&lt;InsuranceDto&gt; getInsurances1(listOfIdsDto)

Gets insurances by id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<InsuranceDto> = apiInstance.getInsurances1(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#getInsurances1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#getInsurances1")
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

<a name="listInsurancesByCode1"></a>
# **listInsurancesByCode1**
> kotlin.collections.List&lt;InsuranceDto&gt; listInsurancesByCode1(insuranceCode)

Gets an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceCode : kotlin.String = insuranceCode_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InsuranceDto> = apiInstance.listInsurancesByCode1(insuranceCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#listInsurancesByCode1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#listInsurancesByCode1")
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

<a name="listInsurancesByName1"></a>
# **listInsurancesByName1**
> kotlin.collections.List&lt;InsuranceDto&gt; listInsurancesByName1(insuranceName)

Gets an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceName : kotlin.String = insuranceName_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InsuranceDto> = apiInstance.listInsurancesByName1(insuranceName)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#listInsurancesByName1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#listInsurancesByName1")
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

<a name="modifyInsurance1"></a>
# **modifyInsurance1**
> InsuranceDto modifyInsurance1(insuranceDto)

Modifies an insurance

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InsuranceApi()
val insuranceDto : InsuranceDto =  // InsuranceDto | 
try {
    val result : InsuranceDto = apiInstance.modifyInsurance1(insuranceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InsuranceApi#modifyInsurance1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InsuranceApi#modifyInsurance1")
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

