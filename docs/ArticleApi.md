# ArticleApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createArticle**](ArticleApi.md#createArticle) | **POST** /rest/v1/article | Creates a article
[**deleteArticle**](ArticleApi.md#deleteArticle) | **DELETE** /rest/v1/article/{articleIds} | Deletes an article
[**getArticle**](ArticleApi.md#getArticle) | **GET** /rest/v1/article/{articleId} | Gets an article
[**getArticles**](ArticleApi.md#getArticles) | **GET** /rest/v1/article | Gets all articles
[**modifyArticle**](ArticleApi.md#modifyArticle) | **PUT** /rest/v1/article | Modifies an article


<a name="createArticle"></a>
# **createArticle**
> ArticleDto createArticle(articleDto)

Creates a article

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
val articleDto : ArticleDto =  // ArticleDto | 
try {
    val result : ArticleDto = apiInstance.createArticle(articleDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#createArticle")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#createArticle")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **articleDto** | [**ArticleDto**](ArticleDto.md)|  |

### Return type

[**ArticleDto**](ArticleDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteArticle"></a>
# **deleteArticle**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteArticle(articleIds)

Deletes an article

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
val articleIds : kotlin.String = articleIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteArticle(articleIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#deleteArticle")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#deleteArticle")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **articleIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getArticle"></a>
# **getArticle**
> ArticleDto getArticle(articleId)

Gets an article

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
val articleId : kotlin.String = articleId_example // kotlin.String | 
try {
    val result : ArticleDto = apiInstance.getArticle(articleId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#getArticle")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#getArticle")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **articleId** | **kotlin.String**|  |

### Return type

[**ArticleDto**](ArticleDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getArticles"></a>
# **getArticles**
> kotlin.collections.List&lt;ArticleDto&gt; getArticles()

Gets all articles

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
try {
    val result : kotlin.collections.List<ArticleDto> = apiInstance.getArticles()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#getArticles")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#getArticles")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;ArticleDto&gt;**](ArticleDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyArticle"></a>
# **modifyArticle**
> ArticleDto modifyArticle(articleDto)

Modifies an article

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
val articleDto : ArticleDto =  // ArticleDto | 
try {
    val result : ArticleDto = apiInstance.modifyArticle(articleDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#modifyArticle")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#modifyArticle")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **articleDto** | [**ArticleDto**](ArticleDto.md)|  |

### Return type

[**ArticleDto**](ArticleDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

