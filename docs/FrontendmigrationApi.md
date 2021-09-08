# FrontendmigrationApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createFrontEndMigration**](FrontendmigrationApi.md#createFrontEndMigration) | **POST** /rest/v2/frontendmigration | Creates a front end migration
[**createFrontEndMigration1**](FrontendmigrationApi.md#createFrontEndMigration1) | **POST** /rest/v1/frontendmigration | Creates a front end migration
[**deleteFrontEndMigration**](FrontendmigrationApi.md#deleteFrontEndMigration) | **DELETE** /rest/v2/frontendmigration/{frontEndMigrationId} | Deletes a front end migration
[**deleteFrontEndMigration1**](FrontendmigrationApi.md#deleteFrontEndMigration1) | **DELETE** /rest/v1/frontendmigration/{frontEndMigrationId} | Deletes a front end migration
[**getFrontEndMigration**](FrontendmigrationApi.md#getFrontEndMigration) | **GET** /rest/v2/frontendmigration/{frontEndMigrationId} | Gets a front end migration
[**getFrontEndMigration1**](FrontendmigrationApi.md#getFrontEndMigration1) | **GET** /rest/v1/frontendmigration/{frontEndMigrationId} | Gets a front end migration
[**getFrontEndMigrationByName**](FrontendmigrationApi.md#getFrontEndMigrationByName) | **GET** /rest/v2/frontendmigration/byName/{frontEndMigrationName} | Gets an front end migration
[**getFrontEndMigrationByName1**](FrontendmigrationApi.md#getFrontEndMigrationByName1) | **GET** /rest/v1/frontendmigration/byName/{frontEndMigrationName} | Gets an front end migration
[**getFrontEndMigrations**](FrontendmigrationApi.md#getFrontEndMigrations) | **GET** /rest/v2/frontendmigration | Gets a front end migration
[**getFrontEndMigrations1**](FrontendmigrationApi.md#getFrontEndMigrations1) | **GET** /rest/v1/frontendmigration | Gets a front end migration
[**modifyFrontEndMigration**](FrontendmigrationApi.md#modifyFrontEndMigration) | **PUT** /rest/v2/frontendmigration | Modifies a front end migration
[**modifyFrontEndMigration1**](FrontendmigrationApi.md#modifyFrontEndMigration1) | **PUT** /rest/v1/frontendmigration | Modifies a front end migration


<a name="createFrontEndMigration"></a>
# **createFrontEndMigration**
> FrontEndMigrationDto createFrontEndMigration(frontEndMigrationDto)

Creates a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationDto : FrontEndMigrationDto =  // FrontEndMigrationDto | 
try {
    val result : FrontEndMigrationDto = apiInstance.createFrontEndMigration(frontEndMigrationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#createFrontEndMigration")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#createFrontEndMigration")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationDto** | [**FrontEndMigrationDto**](FrontEndMigrationDto.md)|  |

### Return type

[**FrontEndMigrationDto**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createFrontEndMigration1"></a>
# **createFrontEndMigration1**
> FrontEndMigrationDto createFrontEndMigration1(frontEndMigrationDto)

Creates a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationDto : FrontEndMigrationDto =  // FrontEndMigrationDto | 
try {
    val result : FrontEndMigrationDto = apiInstance.createFrontEndMigration1(frontEndMigrationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#createFrontEndMigration1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#createFrontEndMigration1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationDto** | [**FrontEndMigrationDto**](FrontEndMigrationDto.md)|  |

### Return type

[**FrontEndMigrationDto**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteFrontEndMigration"></a>
# **deleteFrontEndMigration**
> DocIdentifier deleteFrontEndMigration(frontEndMigrationId)

Deletes a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationId : kotlin.String = frontEndMigrationId_example // kotlin.String | 
try {
    val result : DocIdentifier = apiInstance.deleteFrontEndMigration(frontEndMigrationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#deleteFrontEndMigration")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#deleteFrontEndMigration")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationId** | **kotlin.String**|  |

### Return type

[**DocIdentifier**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deleteFrontEndMigration1"></a>
# **deleteFrontEndMigration1**
> DocIdentifier deleteFrontEndMigration1(frontEndMigrationId)

Deletes a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationId : kotlin.String = frontEndMigrationId_example // kotlin.String | 
try {
    val result : DocIdentifier = apiInstance.deleteFrontEndMigration1(frontEndMigrationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#deleteFrontEndMigration1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#deleteFrontEndMigration1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationId** | **kotlin.String**|  |

### Return type

[**DocIdentifier**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFrontEndMigration"></a>
# **getFrontEndMigration**
> FrontEndMigrationDto getFrontEndMigration(frontEndMigrationId)

Gets a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationId : kotlin.String = frontEndMigrationId_example // kotlin.String | 
try {
    val result : FrontEndMigrationDto = apiInstance.getFrontEndMigration(frontEndMigrationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#getFrontEndMigration")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#getFrontEndMigration")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationId** | **kotlin.String**|  |

### Return type

[**FrontEndMigrationDto**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFrontEndMigration1"></a>
# **getFrontEndMigration1**
> FrontEndMigrationDto getFrontEndMigration1(frontEndMigrationId)

Gets a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationId : kotlin.String = frontEndMigrationId_example // kotlin.String | 
try {
    val result : FrontEndMigrationDto = apiInstance.getFrontEndMigration1(frontEndMigrationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#getFrontEndMigration1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#getFrontEndMigration1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationId** | **kotlin.String**|  |

### Return type

[**FrontEndMigrationDto**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFrontEndMigrationByName"></a>
# **getFrontEndMigrationByName**
> kotlin.collections.List&lt;FrontEndMigrationDto&gt; getFrontEndMigrationByName(frontEndMigrationName)

Gets an front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationName : kotlin.String = frontEndMigrationName_example // kotlin.String | 
try {
    val result : kotlin.collections.List<FrontEndMigrationDto> = apiInstance.getFrontEndMigrationByName(frontEndMigrationName)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#getFrontEndMigrationByName")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#getFrontEndMigrationByName")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationName** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;FrontEndMigrationDto&gt;**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFrontEndMigrationByName1"></a>
# **getFrontEndMigrationByName1**
> kotlin.collections.List&lt;FrontEndMigrationDto&gt; getFrontEndMigrationByName1(frontEndMigrationName)

Gets an front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationName : kotlin.String = frontEndMigrationName_example // kotlin.String | 
try {
    val result : kotlin.collections.List<FrontEndMigrationDto> = apiInstance.getFrontEndMigrationByName1(frontEndMigrationName)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#getFrontEndMigrationByName1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#getFrontEndMigrationByName1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationName** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;FrontEndMigrationDto&gt;**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFrontEndMigrations"></a>
# **getFrontEndMigrations**
> kotlin.collections.List&lt;FrontEndMigrationDto&gt; getFrontEndMigrations()

Gets a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
try {
    val result : kotlin.collections.List<FrontEndMigrationDto> = apiInstance.getFrontEndMigrations()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#getFrontEndMigrations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#getFrontEndMigrations")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;FrontEndMigrationDto&gt;**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFrontEndMigrations1"></a>
# **getFrontEndMigrations1**
> kotlin.collections.List&lt;FrontEndMigrationDto&gt; getFrontEndMigrations1()

Gets a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
try {
    val result : kotlin.collections.List<FrontEndMigrationDto> = apiInstance.getFrontEndMigrations1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#getFrontEndMigrations1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#getFrontEndMigrations1")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;FrontEndMigrationDto&gt;**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyFrontEndMigration"></a>
# **modifyFrontEndMigration**
> FrontEndMigrationDto modifyFrontEndMigration(frontEndMigrationDto)

Modifies a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationDto : FrontEndMigrationDto =  // FrontEndMigrationDto | 
try {
    val result : FrontEndMigrationDto = apiInstance.modifyFrontEndMigration(frontEndMigrationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#modifyFrontEndMigration")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#modifyFrontEndMigration")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationDto** | [**FrontEndMigrationDto**](FrontEndMigrationDto.md)|  |

### Return type

[**FrontEndMigrationDto**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyFrontEndMigration1"></a>
# **modifyFrontEndMigration1**
> FrontEndMigrationDto modifyFrontEndMigration1(frontEndMigrationDto)

Modifies a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontendmigrationApi()
val frontEndMigrationDto : FrontEndMigrationDto =  // FrontEndMigrationDto | 
try {
    val result : FrontEndMigrationDto = apiInstance.modifyFrontEndMigration1(frontEndMigrationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontendmigrationApi#modifyFrontEndMigration1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontendmigrationApi#modifyFrontEndMigration1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **frontEndMigrationDto** | [**FrontEndMigrationDto**](FrontEndMigrationDto.md)|  |

### Return type

[**FrontEndMigrationDto**](FrontEndMigrationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

