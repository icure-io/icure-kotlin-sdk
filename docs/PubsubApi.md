# PubsubApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**offerAuth**](PubsubApi.md#offerAuth) | **PUT** /rest/v1/pubsub/auth/{bucket} | Offer auth data on secret bucket
[**pub**](PubsubApi.md#pub) | **PUT** /rest/v1/pubsub/pub/{key} | publish data
[**recoverAuth**](PubsubApi.md#recoverAuth) | **GET** /rest/v1/pubsub/auth/recover/{bucket} | Recover auth data from secret bucket
[**sub**](PubsubApi.md#sub) | **GET** /rest/v1/pubsub/sub/{key} | subscribe to data


<a name="offerAuth"></a>
# **offerAuth**
> kotlin.collections.Map&lt;kotlin.String, kotlin.Boolean&gt; offerAuth(bucket, body)

Offer auth data on secret bucket

Offer auth data on previously agreed on secret bucket, data should be encrypted

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubsubApi()
val bucket : kotlin.String = bucket_example // kotlin.String | 
val body : kotlin.ByteArray = BYTE_ARRAY_DATA_HERE // kotlin.ByteArray | 
try {
    val result : kotlin.collections.Map<kotlin.String, kotlin.Boolean> = apiInstance.offerAuth(bucket, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubsubApi#offerAuth")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubsubApi#offerAuth")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **bucket** | **kotlin.String**|  |
 **body** | **kotlin.ByteArray**|  |

### Return type

**kotlin.collections.Map&lt;kotlin.String, kotlin.Boolean&gt;**

### Authorization


Configure basicScheme:
    ApiClient.username = ""
    ApiClient.password = ""

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

<a name="pub"></a>
# **pub**
> kotlin.collections.Map&lt;kotlin.String, kotlin.Boolean&gt; pub(key, body)

publish data

Publish value with key

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubsubApi()
val key : kotlin.String = key_example // kotlin.String | 
val body : kotlin.ByteArray = BYTE_ARRAY_DATA_HERE // kotlin.ByteArray | 
try {
    val result : kotlin.collections.Map<kotlin.String, kotlin.Boolean> = apiInstance.pub(key, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubsubApi#pub")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubsubApi#pub")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key** | **kotlin.String**|  |
 **body** | **kotlin.ByteArray**|  |

### Return type

**kotlin.collections.Map&lt;kotlin.String, kotlin.Boolean&gt;**

### Authorization


Configure basicScheme:
    ApiClient.username = ""
    ApiClient.password = ""

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: */*

<a name="recoverAuth"></a>
# **recoverAuth**
> java.io.File recoverAuth(bucket)

Recover auth data from secret bucket

Recover auth data from bucket, data should be encrypted

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubsubApi()
val bucket : kotlin.String = bucket_example // kotlin.String | 
try {
    val result : java.io.File = apiInstance.recoverAuth(bucket)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubsubApi#recoverAuth")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubsubApi#recoverAuth")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **bucket** | **kotlin.String**|  |

### Return type

[**java.io.File**](java.io.File.md)

### Authorization


Configure basicScheme:
    ApiClient.username = ""
    ApiClient.password = ""

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

<a name="sub"></a>
# **sub**
> java.io.File sub(key)

subscribe to data

Try to get published data

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubsubApi()
val key : kotlin.String = key_example // kotlin.String | 
try {
    val result : java.io.File = apiInstance.sub(key)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubsubApi#sub")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubsubApi#sub")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key** | **kotlin.String**|  |

### Return type

[**java.io.File**](java.io.File.md)

### Authorization


Configure basicScheme:
    ApiClient.username = ""
    ApiClient.password = ""

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

