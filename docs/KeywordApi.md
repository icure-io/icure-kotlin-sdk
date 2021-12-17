# KeywordApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createKeyword**](KeywordApi.md#createKeyword) | **POST** /rest/v2/keyword | Create a keyword with the current user
[**deleteKeywords**](KeywordApi.md#deleteKeywords) | **POST** /rest/v2/keyword/delete/batch | Delete keywords.
[**getKeyword**](KeywordApi.md#getKeyword) | **GET** /rest/v2/keyword/{keywordId} | Get a keyword
[**getKeywords**](KeywordApi.md#getKeywords) | **GET** /rest/v2/keyword | Gets all keywords
[**getKeywordsByUser**](KeywordApi.md#getKeywordsByUser) | **GET** /rest/v2/keyword/byUser/{userId} | Get keywords by user
[**modifyKeyword**](KeywordApi.md#modifyKeyword) | **PUT** /rest/v2/keyword | Modify a keyword


<a name="createKeyword"></a>
# **createKeyword**
> KeywordDto createKeyword(keywordDto)

Create a keyword with the current user

Returns an instance of created keyword.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = KeywordApi()
val keywordDto : KeywordDto =  // KeywordDto | 
try {
    val result : KeywordDto = apiInstance.createKeyword(keywordDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling KeywordApi#createKeyword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling KeywordApi#createKeyword")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keywordDto** | [**KeywordDto**](KeywordDto.md)|  |

### Return type

[**KeywordDto**](KeywordDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteKeywords"></a>
# **deleteKeywords**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteKeywords(listOfIdsDto)

Delete keywords.

Response is a set containing the ID&#39;s of deleted keywords.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = KeywordApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteKeywords(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling KeywordApi#deleteKeywords")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling KeywordApi#deleteKeywords")
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

<a name="getKeyword"></a>
# **getKeyword**
> KeywordDto getKeyword(keywordId)

Get a keyword

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = KeywordApi()
val keywordId : kotlin.String = keywordId_example // kotlin.String | 
try {
    val result : KeywordDto = apiInstance.getKeyword(keywordId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling KeywordApi#getKeyword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling KeywordApi#getKeyword")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keywordId** | **kotlin.String**|  |

### Return type

[**KeywordDto**](KeywordDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getKeywords"></a>
# **getKeywords**
> kotlin.collections.List&lt;KeywordDto&gt; getKeywords()

Gets all keywords

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = KeywordApi()
try {
    val result : kotlin.collections.List<KeywordDto> = apiInstance.getKeywords()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling KeywordApi#getKeywords")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling KeywordApi#getKeywords")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;KeywordDto&gt;**](KeywordDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getKeywordsByUser"></a>
# **getKeywordsByUser**
> kotlin.collections.List&lt;KeywordDto&gt; getKeywordsByUser(userId)

Get keywords by user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = KeywordApi()
val userId : kotlin.String = userId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<KeywordDto> = apiInstance.getKeywordsByUser(userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling KeywordApi#getKeywordsByUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling KeywordApi#getKeywordsByUser")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;KeywordDto&gt;**](KeywordDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyKeyword"></a>
# **modifyKeyword**
> KeywordDto modifyKeyword(keywordDto)

Modify a keyword

Returns the modified keyword.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = KeywordApi()
val keywordDto : KeywordDto =  // KeywordDto | 
try {
    val result : KeywordDto = apiInstance.modifyKeyword(keywordDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling KeywordApi#modifyKeyword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling KeywordApi#modifyKeyword")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **keywordDto** | [**KeywordDto**](KeywordDto.md)|  |

### Return type

[**KeywordDto**](KeywordDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

