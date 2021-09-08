# ArticleApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createArticle**](ArticleApi.md#createArticle) | **POST** /rest/v2/article | Creates a article
[**createArticle1**](ArticleApi.md#createArticle1) | **POST** /rest/v1/article | Creates a article
[**deleteArticle**](ArticleApi.md#deleteArticle) | **DELETE** /rest/v1/article/{articleIds} | Deletes an article
[**deleteArticles**](ArticleApi.md#deleteArticles) | **POST** /rest/v2/article/delete/batch | Deletes articles
[**getArticle**](ArticleApi.md#getArticle) | **GET** /rest/v2/article/{articleId} | Gets an article
[**getArticle1**](ArticleApi.md#getArticle1) | **GET** /rest/v1/article/{articleId} | Gets an article
[**getArticles**](ArticleApi.md#getArticles) | **GET** /rest/v2/article | Gets all articles
[**getArticles1**](ArticleApi.md#getArticles1) | **GET** /rest/v1/article | Gets all articles
[**modifyArticle**](ArticleApi.md#modifyArticle) | **PUT** /rest/v2/article | Modifies an article
[**modifyArticle1**](ArticleApi.md#modifyArticle1) | **PUT** /rest/v1/article | Modifies an article


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

<a name="createArticle1"></a>
# **createArticle1**
> ArticleDto createArticle1(articleDto)

Creates a article

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
val articleDto : ArticleDto =  // ArticleDto | 
try {
    val result : ArticleDto = apiInstance.createArticle1(articleDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#createArticle1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#createArticle1")
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

<a name="deleteArticles"></a>
# **deleteArticles**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteArticles(listOfIdsDto)

Deletes articles

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteArticles(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#deleteArticles")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#deleteArticles")
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

<a name="getArticle1"></a>
# **getArticle1**
> ArticleDto getArticle1(articleId)

Gets an article

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
val articleId : kotlin.String = articleId_example // kotlin.String | 
try {
    val result : ArticleDto = apiInstance.getArticle1(articleId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#getArticle1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#getArticle1")
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

<a name="getArticles1"></a>
# **getArticles1**
> kotlin.collections.List&lt;ArticleDto&gt; getArticles1()

Gets all articles

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
try {
    val result : kotlin.collections.List<ArticleDto> = apiInstance.getArticles1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#getArticles1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#getArticles1")
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

<a name="modifyArticle1"></a>
# **modifyArticle1**
> ArticleDto modifyArticle1(articleDto)

Modifies an article

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ArticleApi()
val articleDto : ArticleDto =  // ArticleDto | 
try {
    val result : ArticleDto = apiInstance.modifyArticle1(articleDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ArticleApi#modifyArticle1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ArticleApi#modifyArticle1")
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

