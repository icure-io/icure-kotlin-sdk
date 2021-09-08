# EntityrefApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createEntityReference**](EntityrefApi.md#createEntityReference) | **POST** /rest/v2/entityref | Create an entity reference
[**createEntityReference1**](EntityrefApi.md#createEntityReference1) | **POST** /rest/v1/entityref | Create an entity reference
[**getLatest**](EntityrefApi.md#getLatest) | **GET** /rest/v2/entityref/latest/{prefix} | Find latest reference for a prefix 
[**getLatest1**](EntityrefApi.md#getLatest1) | **GET** /rest/v1/entityref/latest/{prefix} | Find latest reference for a prefix 


<a name="createEntityReference"></a>
# **createEntityReference**
> EntityReferenceDto createEntityReference(entityReferenceDto)

Create an entity reference

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityrefApi()
val entityReferenceDto : EntityReferenceDto =  // EntityReferenceDto | 
try {
    val result : EntityReferenceDto = apiInstance.createEntityReference(entityReferenceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityrefApi#createEntityReference")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityrefApi#createEntityReference")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityReferenceDto** | [**EntityReferenceDto**](EntityReferenceDto.md)|  |

### Return type

[**EntityReferenceDto**](EntityReferenceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createEntityReference1"></a>
# **createEntityReference1**
> EntityReferenceDto createEntityReference1(entityReferenceDto)

Create an entity reference

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityrefApi()
val entityReferenceDto : EntityReferenceDto =  // EntityReferenceDto | 
try {
    val result : EntityReferenceDto = apiInstance.createEntityReference1(entityReferenceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityrefApi#createEntityReference1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityrefApi#createEntityReference1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityReferenceDto** | [**EntityReferenceDto**](EntityReferenceDto.md)|  |

### Return type

[**EntityReferenceDto**](EntityReferenceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getLatest"></a>
# **getLatest**
> EntityReferenceDto getLatest(prefix)

Find latest reference for a prefix 

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityrefApi()
val prefix : kotlin.String = prefix_example // kotlin.String | 
try {
    val result : EntityReferenceDto = apiInstance.getLatest(prefix)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityrefApi#getLatest")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityrefApi#getLatest")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **prefix** | **kotlin.String**|  |

### Return type

[**EntityReferenceDto**](EntityReferenceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getLatest1"></a>
# **getLatest1**
> EntityReferenceDto getLatest1(prefix)

Find latest reference for a prefix 

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityrefApi()
val prefix : kotlin.String = prefix_example // kotlin.String | 
try {
    val result : EntityReferenceDto = apiInstance.getLatest1(prefix)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityrefApi#getLatest1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityrefApi#getLatest1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **prefix** | **kotlin.String**|  |

### Return type

[**EntityReferenceDto**](EntityReferenceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

