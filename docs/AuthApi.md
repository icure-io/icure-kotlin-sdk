# AuthApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**login**](AuthApi.md#login) | **POST** /rest/v1/auth/login | login
[**logout**](AuthApi.md#logout) | **GET** /rest/v1/auth/logout | logout
[**logoutPost**](AuthApi.md#logoutPost) | **POST** /rest/v1/auth/logout | logout
[**token**](AuthApi.md#token) | **GET** /rest/v1/auth/token/{method}/{path} | token


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


Configure basicScheme:
    ApiClient.username = ""
    ApiClient.password = ""

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


Configure basicScheme:
    ApiClient.username = ""
    ApiClient.password = ""

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


Configure basicScheme:
    ApiClient.username = ""
    ApiClient.password = ""

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


Configure basicScheme:
    ApiClient.username = ""
    ApiClient.password = ""

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

