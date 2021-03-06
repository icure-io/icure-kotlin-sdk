# TarificationApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createTarification**](TarificationApi.md#createTarification) | **POST** /rest/v2/tarification | Create a Tarification
[**findTarificationsBy**](TarificationApi.md#findTarificationsBy) | **GET** /rest/v2/tarification | Finding tarifications by tarification, type and version with pagination.
[**findTarificationsBy1**](TarificationApi.md#findTarificationsBy1) | **GET** /rest/v2/tarification/byRegionTypeTarification | Finding tarifications by tarification, type and version
[**findTarificationsByLabel**](TarificationApi.md#findTarificationsByLabel) | **GET** /rest/v2/tarification/byLabel | Finding tarifications by tarification, type and version with pagination.
[**getTarification**](TarificationApi.md#getTarification) | **GET** /rest/v2/tarification/{tarificationId} | Get a tarification
[**getTarificationWithParts**](TarificationApi.md#getTarificationWithParts) | **GET** /rest/v2/tarification/{type}/{tarification}/{version} | Get a tarification
[**getTarifications**](TarificationApi.md#getTarifications) | **POST** /rest/v2/tarification/byIds | Get a list of tarifications by ids
[**modifyTarification**](TarificationApi.md#modifyTarification) | **PUT** /rest/v2/tarification | Modify a tarification


<a name="createTarification"></a>
# **createTarification**
> TarificationDto createTarification(tarificationDto)

Create a Tarification

Type, Tarification and Version are required.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TarificationApi()
val tarificationDto : TarificationDto =  // TarificationDto | 
try {
    val result : TarificationDto = apiInstance.createTarification(tarificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TarificationApi#createTarification")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TarificationApi#createTarification")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **tarificationDto** | [**TarificationDto**](TarificationDto.md)|  |

### Return type

[**TarificationDto**](TarificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findTarificationsBy"></a>
# **findTarificationsBy**
> PaginatedListTarificationDto findTarificationsBy(region, type, tarification, version, startDocumentId, startKey, limit)

Finding tarifications by tarification, type and version with pagination.

Returns a list of tarifications matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TarificationApi()
val region : kotlin.String = region_example // kotlin.String | 
val type : kotlin.String = type_example // kotlin.String | 
val tarification : kotlin.String = tarification_example // kotlin.String | 
val version : kotlin.String = version_example // kotlin.String | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A tarification document ID
val startKey : kotlin.String = startKey_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListTarificationDto = apiInstance.findTarificationsBy(region, type, tarification, version, startDocumentId, startKey, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TarificationApi#findTarificationsBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TarificationApi#findTarificationsBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **region** | **kotlin.String**|  | [optional]
 **type** | **kotlin.String**|  | [optional]
 **tarification** | **kotlin.String**|  | [optional]
 **version** | **kotlin.String**|  | [optional]
 **startDocumentId** | **kotlin.String**| A tarification document ID | [optional]
 **startKey** | **kotlin.String**|  | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListTarificationDto**](PaginatedListTarificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findTarificationsBy1"></a>
# **findTarificationsBy1**
> kotlin.collections.List&lt;TarificationDto&gt; findTarificationsBy1(region, type, tarification, version)

Finding tarifications by tarification, type and version

Returns a list of tarifications matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TarificationApi()
val region : kotlin.String = region_example // kotlin.String | Tarification region
val type : kotlin.String = type_example // kotlin.String | Tarification type
val tarification : kotlin.String = tarification_example // kotlin.String | Tarification tarification
val version : kotlin.String = version_example // kotlin.String | Tarification version
try {
    val result : kotlin.collections.List<TarificationDto> = apiInstance.findTarificationsBy1(region, type, tarification, version)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TarificationApi#findTarificationsBy1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TarificationApi#findTarificationsBy1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **region** | **kotlin.String**| Tarification region | [optional]
 **type** | **kotlin.String**| Tarification type | [optional]
 **tarification** | **kotlin.String**| Tarification tarification | [optional]
 **version** | **kotlin.String**| Tarification version | [optional]

### Return type

[**kotlin.collections.List&lt;TarificationDto&gt;**](TarificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findTarificationsByLabel"></a>
# **findTarificationsByLabel**
> PaginatedListTarificationDto findTarificationsByLabel(region, types, language, label, startKey, startDocumentId, limit)

Finding tarifications by tarification, type and version with pagination.

Returns a list of tarifications matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TarificationApi()
val region : kotlin.String = region_example // kotlin.String | 
val types : kotlin.String = types_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val label : kotlin.String = label_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A tarification document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListTarificationDto = apiInstance.findTarificationsByLabel(region, types, language, label, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TarificationApi#findTarificationsByLabel")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TarificationApi#findTarificationsByLabel")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **region** | **kotlin.String**|  | [optional]
 **types** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **label** | **kotlin.String**|  | [optional]
 **startKey** | **kotlin.String**|  | [optional]
 **startDocumentId** | **kotlin.String**| A tarification document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListTarificationDto**](PaginatedListTarificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTarification"></a>
# **getTarification**
> TarificationDto getTarification(tarificationId)

Get a tarification

Get a tarification based on ID or (tarification,type,version) as query strings. (tarification,type,version) is unique.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TarificationApi()
val tarificationId : kotlin.String = tarificationId_example // kotlin.String | Tarification id
try {
    val result : TarificationDto = apiInstance.getTarification(tarificationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TarificationApi#getTarification")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TarificationApi#getTarification")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **tarificationId** | **kotlin.String**| Tarification id |

### Return type

[**TarificationDto**](TarificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTarificationWithParts"></a>
# **getTarificationWithParts**
> TarificationDto getTarificationWithParts(type, tarification, version)

Get a tarification

Get a tarification based on ID or (tarification,type,version) as query strings. (tarification,type,version) is unique.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TarificationApi()
val type : kotlin.String = type_example // kotlin.String | Tarification type
val tarification : kotlin.String = tarification_example // kotlin.String | Tarification tarification
val version : kotlin.String = version_example // kotlin.String | Tarification version
try {
    val result : TarificationDto = apiInstance.getTarificationWithParts(type, tarification, version)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TarificationApi#getTarificationWithParts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TarificationApi#getTarificationWithParts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **type** | **kotlin.String**| Tarification type |
 **tarification** | **kotlin.String**| Tarification tarification |
 **version** | **kotlin.String**| Tarification version |

### Return type

[**TarificationDto**](TarificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTarifications"></a>
# **getTarifications**
> kotlin.collections.List&lt;TarificationDto&gt; getTarifications(listOfIdsDto)

Get a list of tarifications by ids

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TarificationApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<TarificationDto> = apiInstance.getTarifications(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TarificationApi#getTarifications")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TarificationApi#getTarifications")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;TarificationDto&gt;**](TarificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTarification"></a>
# **modifyTarification**
> TarificationDto modifyTarification(tarificationDto)

Modify a tarification

Modification of (type, tarification, version) is not allowed.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TarificationApi()
val tarificationDto : TarificationDto =  // TarificationDto | 
try {
    val result : TarificationDto = apiInstance.modifyTarification(tarificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TarificationApi#modifyTarification")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TarificationApi#modifyTarification")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **tarificationDto** | [**TarificationDto**](TarificationDto.md)|  |

### Return type

[**TarificationDto**](TarificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

