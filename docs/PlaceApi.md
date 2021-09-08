# PlaceApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createPlace**](PlaceApi.md#createPlace) | **POST** /rest/v2/place | Creates a place
[**createPlace1**](PlaceApi.md#createPlace1) | **POST** /rest/v1/place | Creates a place
[**deletePlace**](PlaceApi.md#deletePlace) | **DELETE** /rest/v1/place/{placeIds} | Deletes an place
[**deletePlaces**](PlaceApi.md#deletePlaces) | **POST** /rest/v2/place/delete/batch | Deletes places
[**getPlace**](PlaceApi.md#getPlace) | **GET** /rest/v2/place/{placeId} | Gets an place
[**getPlace1**](PlaceApi.md#getPlace1) | **GET** /rest/v1/place/{placeId} | Gets an place
[**getPlaces**](PlaceApi.md#getPlaces) | **GET** /rest/v2/place | Gets all places
[**getPlaces1**](PlaceApi.md#getPlaces1) | **GET** /rest/v1/place | Gets all places
[**modifyPlace**](PlaceApi.md#modifyPlace) | **PUT** /rest/v2/place | Modifies an place
[**modifyPlace1**](PlaceApi.md#modifyPlace1) | **PUT** /rest/v1/place | Modifies an place


<a name="createPlace"></a>
# **createPlace**
> PlaceDto createPlace(placeDto)

Creates a place

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
val placeDto : PlaceDto =  // PlaceDto | 
try {
    val result : PlaceDto = apiInstance.createPlace(placeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#createPlace")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#createPlace")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **placeDto** | [**PlaceDto**](PlaceDto.md)|  |

### Return type

[**PlaceDto**](PlaceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createPlace1"></a>
# **createPlace1**
> PlaceDto createPlace1(placeDto)

Creates a place

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
val placeDto : PlaceDto =  // PlaceDto | 
try {
    val result : PlaceDto = apiInstance.createPlace1(placeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#createPlace1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#createPlace1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **placeDto** | [**PlaceDto**](PlaceDto.md)|  |

### Return type

[**PlaceDto**](PlaceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deletePlace"></a>
# **deletePlace**
> kotlin.collections.List&lt;DocIdentifier&gt; deletePlace(placeIds)

Deletes an place

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
val placeIds : kotlin.String = placeIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deletePlace(placeIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#deletePlace")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#deletePlace")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **placeIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deletePlaces"></a>
# **deletePlaces**
> kotlin.collections.List&lt;DocIdentifier&gt; deletePlaces(listOfIdsDto)

Deletes places

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deletePlaces(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#deletePlaces")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#deletePlaces")
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

<a name="getPlace"></a>
# **getPlace**
> PlaceDto getPlace(placeId)

Gets an place

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
val placeId : kotlin.String = placeId_example // kotlin.String | 
try {
    val result : PlaceDto = apiInstance.getPlace(placeId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#getPlace")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#getPlace")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **placeId** | **kotlin.String**|  |

### Return type

[**PlaceDto**](PlaceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getPlace1"></a>
# **getPlace1**
> PlaceDto getPlace1(placeId)

Gets an place

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
val placeId : kotlin.String = placeId_example // kotlin.String | 
try {
    val result : PlaceDto = apiInstance.getPlace1(placeId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#getPlace1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#getPlace1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **placeId** | **kotlin.String**|  |

### Return type

[**PlaceDto**](PlaceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getPlaces"></a>
# **getPlaces**
> kotlin.collections.List&lt;PlaceDto&gt; getPlaces()

Gets all places

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
try {
    val result : kotlin.collections.List<PlaceDto> = apiInstance.getPlaces()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#getPlaces")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#getPlaces")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;PlaceDto&gt;**](PlaceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getPlaces1"></a>
# **getPlaces1**
> kotlin.collections.List&lt;PlaceDto&gt; getPlaces1()

Gets all places

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
try {
    val result : kotlin.collections.List<PlaceDto> = apiInstance.getPlaces1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#getPlaces1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#getPlaces1")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;PlaceDto&gt;**](PlaceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyPlace"></a>
# **modifyPlace**
> PlaceDto modifyPlace(placeDto)

Modifies an place

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
val placeDto : PlaceDto =  // PlaceDto | 
try {
    val result : PlaceDto = apiInstance.modifyPlace(placeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#modifyPlace")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#modifyPlace")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **placeDto** | [**PlaceDto**](PlaceDto.md)|  |

### Return type

[**PlaceDto**](PlaceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyPlace1"></a>
# **modifyPlace1**
> PlaceDto modifyPlace1(placeDto)

Modifies an place

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PlaceApi()
val placeDto : PlaceDto =  // PlaceDto | 
try {
    val result : PlaceDto = apiInstance.modifyPlace1(placeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PlaceApi#modifyPlace1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PlaceApi#modifyPlace1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **placeDto** | [**PlaceDto**](PlaceDto.md)|  |

### Return type

[**PlaceDto**](PlaceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

