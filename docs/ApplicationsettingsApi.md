# ApplicationsettingsApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createApplicationSettings**](ApplicationsettingsApi.md#createApplicationSettings) | **POST** /rest/v2/appsettings | Create new application settings
[**getApplicationSettings**](ApplicationsettingsApi.md#getApplicationSettings) | **GET** /rest/v2/appsettings | Gets all application settings
[**updateApplicationSettings**](ApplicationsettingsApi.md#updateApplicationSettings) | **PUT** /rest/v2/appsettings | Update application settings


<a name="createApplicationSettings"></a>
# **createApplicationSettings**
> ApplicationSettingsDto createApplicationSettings(applicationSettingsDto)

Create new application settings

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ApplicationsettingsApi()
val applicationSettingsDto : ApplicationSettingsDto =  // ApplicationSettingsDto | 
try {
    val result : ApplicationSettingsDto = apiInstance.createApplicationSettings(applicationSettingsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ApplicationsettingsApi#createApplicationSettings")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ApplicationsettingsApi#createApplicationSettings")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **applicationSettingsDto** | [**ApplicationSettingsDto**](ApplicationSettingsDto.md)|  |

### Return type

[**ApplicationSettingsDto**](ApplicationSettingsDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getApplicationSettings"></a>
# **getApplicationSettings**
> kotlin.collections.List&lt;ApplicationSettingsDto&gt; getApplicationSettings()

Gets all application settings

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ApplicationsettingsApi()
try {
    val result : kotlin.collections.List<ApplicationSettingsDto> = apiInstance.getApplicationSettings()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ApplicationsettingsApi#getApplicationSettings")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ApplicationsettingsApi#getApplicationSettings")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;ApplicationSettingsDto&gt;**](ApplicationSettingsDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="updateApplicationSettings"></a>
# **updateApplicationSettings**
> ApplicationSettingsDto updateApplicationSettings(applicationSettingsDto)

Update application settings

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ApplicationsettingsApi()
val applicationSettingsDto : ApplicationSettingsDto =  // ApplicationSettingsDto | 
try {
    val result : ApplicationSettingsDto = apiInstance.updateApplicationSettings(applicationSettingsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ApplicationsettingsApi#updateApplicationSettings")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ApplicationsettingsApi#updateApplicationSettings")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **applicationSettingsDto** | [**ApplicationSettingsDto**](ApplicationSettingsDto.md)|  |

### Return type

[**ApplicationSettingsDto**](ApplicationSettingsDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

