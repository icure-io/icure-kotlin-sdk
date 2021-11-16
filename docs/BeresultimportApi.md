# BeresultimportApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**canHandle**](BeresultimportApi.md#canHandle) | **GET** /rest/v1/be_result_import/canhandle/{id} | Can we handle this document
[**doImport**](BeresultimportApi.md#doImport) | **GET** /rest/v1/be_result_import/import/{documentId}/{hcpId}/{language} | import document
[**getInfos**](BeresultimportApi.md#getInfos) | **GET** /rest/v1/be_result_import/infos/{id} | Extract general infos from document


<a name="canHandle"></a>
# **canHandle**
> kotlin.Boolean canHandle(id, enckeys)

Can we handle this document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BeresultimportApi()
val id : kotlin.String = id_example // kotlin.String | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
try {
    val result : kotlin.Boolean = apiInstance.canHandle(id, enckeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BeresultimportApi#canHandle")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BeresultimportApi#canHandle")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |
 **enckeys** | **kotlin.String**|  |

### Return type

**kotlin.Boolean**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="doImport"></a>
# **doImport**
> ContactDto doImport(documentId, hcpId, language, protocolIds, formIds, planOfActionId, enckeys, ctc)

import document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BeresultimportApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val protocolIds : kotlin.String = protocolIds_example // kotlin.String | 
val formIds : kotlin.String = formIds_example // kotlin.String | 
val planOfActionId : kotlin.String = planOfActionId_example // kotlin.String | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
val ctc : ContactDto =  // ContactDto | 
try {
    val result : ContactDto = apiInstance.doImport(documentId, hcpId, language, protocolIds, formIds, planOfActionId, enckeys, ctc)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BeresultimportApi#doImport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BeresultimportApi#doImport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **hcpId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **protocolIds** | **kotlin.String**|  |
 **formIds** | **kotlin.String**|  |
 **planOfActionId** | **kotlin.String**|  |
 **enckeys** | **kotlin.String**|  |
 **ctc** | [**ContactDto**](.md)|  |

### Return type

[**ContactDto**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getInfos"></a>
# **getInfos**
> kotlin.collections.List&lt;ResultInfoDto&gt; getInfos(id, language, enckeys, full)

Extract general infos from document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BeresultimportApi()
val id : kotlin.String = id_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val enckeys : kotlin.String = enckeys_example // kotlin.String | 
val full : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<ResultInfoDto> = apiInstance.getInfos(id, language, enckeys, full)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BeresultimportApi#getInfos")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BeresultimportApi#getInfos")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **enckeys** | **kotlin.String**|  |
 **full** | **kotlin.Boolean**|  | [optional]

### Return type

[**kotlin.collections.List&lt;ResultInfoDto&gt;**](ResultInfoDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

