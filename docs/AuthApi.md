# AuthApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**login**](AuthApi.md#login) | **POST** /rest/v2/auth/login | login
[**login1**](AuthApi.md#login1) | **POST** /rest/v1/auth/login | login
[**logout**](AuthApi.md#logout) | **GET** /rest/v2/auth/logout | logout
[**logout1**](AuthApi.md#logout1) | **GET** /rest/v1/auth/logout | logout
[**logoutPost**](AuthApi.md#logoutPost) | **POST** /rest/v2/auth/logout | logout
[**logoutPost1**](AuthApi.md#logoutPost1) | **POST** /rest/v1/auth/logout | logout
[**token**](AuthApi.md#token) | **GET** /rest/v2/auth/token/{method}/{path} | token
[**token1**](AuthApi.md#token1) | **GET** /rest/v1/auth/token/{method}/{path} | token


<a name="login"></a>
# **login**
> AuthenticationResponse login(session)

login

Login using username and password

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AuthApi()
val session : WebSession =  // WebSession | 
try {
    val result : AuthenticationResponse = apiInstance.login(session)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AuthApi#login")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AuthApi#login")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **session** | [**WebSession**](.md)|  |

### Return type

[**AuthenticationResponse**](AuthenticationResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="login1"></a>
# **login1**
> AuthenticationResponse login1(session)

login

Login using username and password

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AuthApi()
val session : WebSession =  // WebSession | 
try {
    val result : AuthenticationResponse = apiInstance.login1(session)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AuthApi#login1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AuthApi#login1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **session** | [**WebSession**](.md)|  |

### Return type

[**AuthenticationResponse**](AuthenticationResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="logout"></a>
# **logout**
> AuthenticationResponse logout()

logout

Logout

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AuthApi()
try {
    val result : AuthenticationResponse = apiInstance.logout()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AuthApi#logout")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AuthApi#logout")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**AuthenticationResponse**](AuthenticationResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="logout1"></a>
# **logout1**
> AuthenticationResponse logout1()

logout

Logout

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AuthApi()
try {
    val result : AuthenticationResponse = apiInstance.logout1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AuthApi#logout1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AuthApi#logout1")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**AuthenticationResponse**](AuthenticationResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="logoutPost"></a>
# **logoutPost**
> AuthenticationResponse logoutPost()

logout

Logout

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AuthApi()
try {
    val result : AuthenticationResponse = apiInstance.logoutPost()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AuthApi#logoutPost")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AuthApi#logoutPost")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**AuthenticationResponse**](AuthenticationResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="logoutPost1"></a>
# **logoutPost1**
> AuthenticationResponse logoutPost1()

logout

Logout

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AuthApi()
try {
    val result : AuthenticationResponse = apiInstance.logoutPost1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AuthApi#logoutPost1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AuthApi#logoutPost1")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**AuthenticationResponse**](AuthenticationResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="token"></a>
# **token**
> kotlin.String token(method, path)

token

Get token for subsequent operation

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AuthApi()
val method : kotlin.String = method_example // kotlin.String | 
val path : kotlin.String = path_example // kotlin.String | 
try {
    val result : kotlin.String = apiInstance.token(method, path)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AuthApi#token")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AuthApi#token")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **method** | **kotlin.String**|  |
 **path** | **kotlin.String**|  |

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="token1"></a>
# **token1**
> kotlin.String token1(method, path)

token

Get token for subsequent operation

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AuthApi()
val method : kotlin.String = method_example // kotlin.String | 
val path : kotlin.String = path_example // kotlin.String | 
try {
    val result : kotlin.String = apiInstance.token1(method, path)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AuthApi#token1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AuthApi#token1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **method** | **kotlin.String**|  |
 **path** | **kotlin.String**|  |

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

