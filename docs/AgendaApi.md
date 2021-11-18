# AgendaApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createAgenda**](AgendaApi.md#createAgenda) | **POST** /rest/v2/agenda | Creates a agenda
[**deleteAgendas**](AgendaApi.md#deleteAgendas) | **POST** /rest/v2/agenda/delete/batch | Deletes agendas
[**getAgenda**](AgendaApi.md#getAgenda) | **GET** /rest/v2/agenda/{agendaId} | Gets an agenda
[**getAgendas**](AgendaApi.md#getAgendas) | **GET** /rest/v2/agenda | Gets all agendas
[**getAgendasForUser**](AgendaApi.md#getAgendasForUser) | **GET** /rest/v2/agenda/byUser | Gets all agendas for user
[**getReadableAgendasForUser**](AgendaApi.md#getReadableAgendasForUser) | **GET** /rest/v2/agenda/readableForUser | Gets readable agendas for user
[**modifyAgenda**](AgendaApi.md#modifyAgenda) | **PUT** /rest/v2/agenda | Modifies an agenda


<a name="createAgenda"></a>
# **createAgenda**
> AgendaDto createAgenda(agendaDto)

Creates a agenda

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AgendaApi()
val agendaDto : AgendaDto =  // AgendaDto | 
try {
    val result : AgendaDto = apiInstance.createAgenda(agendaDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AgendaApi#createAgenda")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AgendaApi#createAgenda")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **agendaDto** | [**AgendaDto**](AgendaDto.md)|  |

### Return type

[**AgendaDto**](AgendaDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteAgendas"></a>
# **deleteAgendas**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteAgendas(listOfIdsDto)

Deletes agendas

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AgendaApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteAgendas(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AgendaApi#deleteAgendas")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AgendaApi#deleteAgendas")
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

<a name="getAgenda"></a>
# **getAgenda**
> AgendaDto getAgenda(agendaId)

Gets an agenda

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AgendaApi()
val agendaId : kotlin.String = agendaId_example // kotlin.String | 
try {
    val result : AgendaDto = apiInstance.getAgenda(agendaId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AgendaApi#getAgenda")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AgendaApi#getAgenda")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **agendaId** | **kotlin.String**|  |

### Return type

[**AgendaDto**](AgendaDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getAgendas"></a>
# **getAgendas**
> kotlin.collections.List&lt;AgendaDto&gt; getAgendas()

Gets all agendas

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AgendaApi()
try {
    val result : kotlin.collections.List<AgendaDto> = apiInstance.getAgendas()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AgendaApi#getAgendas")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AgendaApi#getAgendas")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;AgendaDto&gt;**](AgendaDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getAgendasForUser"></a>
# **getAgendasForUser**
> AgendaDto getAgendasForUser(userId)

Gets all agendas for user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AgendaApi()
val userId : kotlin.String = userId_example // kotlin.String | 
try {
    val result : AgendaDto = apiInstance.getAgendasForUser(userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AgendaApi#getAgendasForUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AgendaApi#getAgendasForUser")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |

### Return type

[**AgendaDto**](AgendaDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getReadableAgendasForUser"></a>
# **getReadableAgendasForUser**
> kotlin.collections.List&lt;AgendaDto&gt; getReadableAgendasForUser(userId)

Gets readable agendas for user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AgendaApi()
val userId : kotlin.String = userId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<AgendaDto> = apiInstance.getReadableAgendasForUser(userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AgendaApi#getReadableAgendasForUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AgendaApi#getReadableAgendasForUser")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;AgendaDto&gt;**](AgendaDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyAgenda"></a>
# **modifyAgenda**
> AgendaDto modifyAgenda(agendaDto)

Modifies an agenda

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = AgendaApi()
val agendaDto : AgendaDto =  // AgendaDto | 
try {
    val result : AgendaDto = apiInstance.modifyAgenda(agendaDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling AgendaApi#modifyAgenda")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling AgendaApi#modifyAgenda")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **agendaDto** | [**AgendaDto**](AgendaDto.md)|  |

### Return type

[**AgendaDto**](AgendaDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

