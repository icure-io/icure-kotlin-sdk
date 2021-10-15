# FrontEndMigrationApi

All URIs are relative to *https://kraken.svc.icure.cloud*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createFrontEndMigration**](FrontEndMigrationApi.md#createFrontEndMigration) | **POST** /rest/v2/frontendmigration | Creates a front end migration
[**deleteFrontEndMigration**](FrontEndMigrationApi.md#deleteFrontEndMigration) | **DELETE** /rest/v2/frontendmigration/{frontEndMigrationId} | Deletes a front end migration
[**getFrontEndMigration**](FrontEndMigrationApi.md#getFrontEndMigration) | **GET** /rest/v2/frontendmigration/{frontEndMigrationId} | Gets a front end migration
[**getFrontEndMigrationByName**](FrontEndMigrationApi.md#getFrontEndMigrationByName) | **GET** /rest/v2/frontendmigration/byName/{frontEndMigrationName} | Gets an front end migration
[**getFrontEndMigrations**](FrontEndMigrationApi.md#getFrontEndMigrations) | **GET** /rest/v2/frontendmigration | Gets a front end migration
[**modifyFrontEndMigration**](FrontEndMigrationApi.md#modifyFrontEndMigration) | **PUT** /rest/v2/frontendmigration | Modifies a front end migration


<a name="createFrontEndMigration"></a>
# **createFrontEndMigration**
> FrontEndMigrationDto createFrontEndMigration(frontEndMigrationDto)

Creates a front end migration

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FrontEndMigrationApi()
val frontEndMigrationDto : FrontEndMigrationDto =  // FrontEndMigrationDto | 
try {
    val result : FrontEndMigrationDto = apiInstance.createFrontEndMigration(frontEndMigrationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontEndMigrationApi#createFrontEndMigration")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontEndMigrationApi#createFrontEndMigration")
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

val apiInstance = FrontEndMigrationApi()
val frontEndMigrationId : kotlin.String = frontEndMigrationId_example // kotlin.String | 
try {
    val result : DocIdentifier = apiInstance.deleteFrontEndMigration(frontEndMigrationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontEndMigrationApi#deleteFrontEndMigration")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontEndMigrationApi#deleteFrontEndMigration")
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

val apiInstance = FrontEndMigrationApi()
val frontEndMigrationId : kotlin.String = frontEndMigrationId_example // kotlin.String | 
try {
    val result : FrontEndMigrationDto = apiInstance.getFrontEndMigration(frontEndMigrationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontEndMigrationApi#getFrontEndMigration")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontEndMigrationApi#getFrontEndMigration")
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

val apiInstance = FrontEndMigrationApi()
val frontEndMigrationName : kotlin.String = frontEndMigrationName_example // kotlin.String | 
try {
    val result : kotlin.collections.List<FrontEndMigrationDto> = apiInstance.getFrontEndMigrationByName(frontEndMigrationName)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontEndMigrationApi#getFrontEndMigrationByName")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontEndMigrationApi#getFrontEndMigrationByName")
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

val apiInstance = FrontEndMigrationApi()
try {
    val result : kotlin.collections.List<FrontEndMigrationDto> = apiInstance.getFrontEndMigrations()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontEndMigrationApi#getFrontEndMigrations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontEndMigrationApi#getFrontEndMigrations")
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

val apiInstance = FrontEndMigrationApi()
val frontEndMigrationDto : FrontEndMigrationDto =  // FrontEndMigrationDto | 
try {
    val result : FrontEndMigrationDto = apiInstance.modifyFrontEndMigration(frontEndMigrationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FrontEndMigrationApi#modifyFrontEndMigration")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FrontEndMigrationApi#modifyFrontEndMigration")
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

