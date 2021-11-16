# PubSubControllerApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**pub1**](PubSubControllerApi.md#pub1) | **POST** /ws/v2/pubsub/{topic}/pub | 
[**pub10**](PubSubControllerApi.md#pub10) | **HEAD** /ws/pubsub/{topic}/pub | 
[**pub11**](PubSubControllerApi.md#pub11) | **GET** /ws/pubsub/{topic}/pub | 
[**pub12**](PubSubControllerApi.md#pub12) | **PATCH** /ws/pubsub/{topic}/pub | 
[**pub13**](PubSubControllerApi.md#pub13) | **OPTIONS** /ws/pubsub/{topic}/pub | 
[**pub14**](PubSubControllerApi.md#pub14) | **DELETE** /ws/pubsub/{topic}/pub | 
[**pub2**](PubSubControllerApi.md#pub2) | **PUT** /ws/v2/pubsub/{topic}/pub | 
[**pub3**](PubSubControllerApi.md#pub3) | **HEAD** /ws/v2/pubsub/{topic}/pub | 
[**pub4**](PubSubControllerApi.md#pub4) | **GET** /ws/v2/pubsub/{topic}/pub | 
[**pub5**](PubSubControllerApi.md#pub5) | **PATCH** /ws/v2/pubsub/{topic}/pub | 
[**pub6**](PubSubControllerApi.md#pub6) | **OPTIONS** /ws/v2/pubsub/{topic}/pub | 
[**pub7**](PubSubControllerApi.md#pub7) | **DELETE** /ws/v2/pubsub/{topic}/pub | 
[**pub8**](PubSubControllerApi.md#pub8) | **POST** /ws/pubsub/{topic}/pub | 
[**pub9**](PubSubControllerApi.md#pub9) | **PUT** /ws/pubsub/{topic}/pub | 
[**sub1**](PubSubControllerApi.md#sub1) | **POST** /ws/v2/pubsub/{topic}/sub | 
[**sub10**](PubSubControllerApi.md#sub10) | **HEAD** /ws/pubsub/{topic}/sub | 
[**sub11**](PubSubControllerApi.md#sub11) | **GET** /ws/pubsub/{topic}/sub | 
[**sub12**](PubSubControllerApi.md#sub12) | **PATCH** /ws/pubsub/{topic}/sub | 
[**sub13**](PubSubControllerApi.md#sub13) | **OPTIONS** /ws/pubsub/{topic}/sub | 
[**sub14**](PubSubControllerApi.md#sub14) | **DELETE** /ws/pubsub/{topic}/sub | 
[**sub2**](PubSubControllerApi.md#sub2) | **PUT** /ws/v2/pubsub/{topic}/sub | 
[**sub3**](PubSubControllerApi.md#sub3) | **HEAD** /ws/v2/pubsub/{topic}/sub | 
[**sub4**](PubSubControllerApi.md#sub4) | **GET** /ws/v2/pubsub/{topic}/sub | 
[**sub5**](PubSubControllerApi.md#sub5) | **PATCH** /ws/v2/pubsub/{topic}/sub | 
[**sub6**](PubSubControllerApi.md#sub6) | **OPTIONS** /ws/v2/pubsub/{topic}/sub | 
[**sub7**](PubSubControllerApi.md#sub7) | **DELETE** /ws/v2/pubsub/{topic}/sub | 
[**sub8**](PubSubControllerApi.md#sub8) | **POST** /ws/pubsub/{topic}/sub | 
[**sub9**](PubSubControllerApi.md#sub9) | **PUT** /ws/pubsub/{topic}/sub | 


<a name="pub1"></a>
# **pub1**
> kotlin.Any pub1(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub1(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub10"></a>
# **pub10**
> kotlin.Any pub10(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub10(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub10")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub10")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub11"></a>
# **pub11**
> kotlin.Any pub11(topic, msg, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val msg : kotlin.String = msg_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.pub11(topic, msg, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub11")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub11")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **msg** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="pub12"></a>
# **pub12**
> kotlin.Any pub12(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub12(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub12")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub12")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub13"></a>
# **pub13**
> kotlin.Any pub13(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub13(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub13")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub13")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub14"></a>
# **pub14**
> kotlin.Any pub14(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub14(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub14")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub14")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub2"></a>
# **pub2**
> kotlin.Any pub2(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub2(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub2")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub2")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub3"></a>
# **pub3**
> kotlin.Any pub3(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub3(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub3")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub3")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub4"></a>
# **pub4**
> kotlin.Any pub4(topic, msg, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val msg : kotlin.String = msg_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.pub4(topic, msg, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub4")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub4")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **msg** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="pub5"></a>
# **pub5**
> kotlin.Any pub5(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub5(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub5")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub5")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub6"></a>
# **pub6**
> kotlin.Any pub6(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub6(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub6")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub6")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub7"></a>
# **pub7**
> kotlin.Any pub7(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub7(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub7")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub7")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub8"></a>
# **pub8**
> kotlin.Any pub8(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub8(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub8")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub8")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="pub9"></a>
# **pub9**
> kotlin.Any pub9(topic, UNKNOWN_PARAMETER_NAME, body)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
val body : kotlin.String = body_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.pub9(topic, UNKNOWN_PARAMETER_NAME, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#pub9")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#pub9")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |
 **body** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="sub1"></a>
# **sub1**
> kotlin.Any sub1(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub1(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub10"></a>
# **sub10**
> kotlin.Any sub10(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub10(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub10")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub10")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub11"></a>
# **sub11**
> kotlin.Any sub11(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub11(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub11")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub11")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub12"></a>
# **sub12**
> kotlin.Any sub12(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub12(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub12")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub12")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub13"></a>
# **sub13**
> kotlin.Any sub13(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub13(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub13")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub13")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub14"></a>
# **sub14**
> kotlin.Any sub14(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub14(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub14")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub14")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub2"></a>
# **sub2**
> kotlin.Any sub2(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub2(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub2")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub2")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub3"></a>
# **sub3**
> kotlin.Any sub3(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub3(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub3")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub3")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub4"></a>
# **sub4**
> kotlin.Any sub4(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub4(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub4")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub4")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub5"></a>
# **sub5**
> kotlin.Any sub5(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub5(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub5")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub5")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub6"></a>
# **sub6**
> kotlin.Any sub6(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub6(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub6")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub6")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub7"></a>
# **sub7**
> kotlin.Any sub7(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub7(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub7")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub7")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub8"></a>
# **sub8**
> kotlin.Any sub8(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub8(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub8")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub8")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="sub9"></a>
# **sub9**
> kotlin.Any sub9(topic, UNKNOWN_PARAMETER_NAME)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PubSubControllerApi()
val topic : kotlin.String = topic_example // kotlin.String | 
val UNKNOWN_PARAMETER_NAME :  =  //  | 
try {
    val result : kotlin.Any = apiInstance.sub9(topic, UNKNOWN_PARAMETER_NAME)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PubSubControllerApi#sub9")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PubSubControllerApi#sub9")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **topic** | **kotlin.String**|  |
 **UNKNOWN_PARAMETER_NAME** | [****](.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

