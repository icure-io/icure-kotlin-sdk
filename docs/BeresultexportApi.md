# BeresultexportApi

All URIs are relative to *https://kraken.svc.icure.cloud*

Method | HTTP request | Description
------------- | ------------- | -------------
[**exportHealthOne**](BeresultexportApi.md#exportHealthOne) | **POST** /rest/v2/be_result_export/hl1/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
[**exportKmehrReport**](BeresultexportApi.md#exportKmehrReport) | **POST** /rest/v2/be_result_export/kmehrreport/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
[**exportMedidoc**](BeresultexportApi.md#exportMedidoc) | **POST** /rest/v2/be_result_export/medidoc/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data


<a name="exportHealthOne"></a>
# **exportHealthOne**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; exportHealthOne(fromHcpId, toHcpId, patId, date, ref, ioIcureKrakenClientInfrastructureByteArrayWrapper)

Export data

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BeresultexportApi()
val fromHcpId : kotlin.String = fromHcpId_example // kotlin.String | 
val toHcpId : kotlin.String = toHcpId_example // kotlin.String | 
val patId : kotlin.String = patId_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val ref : kotlin.String = ref_example // kotlin.String | 
val ioIcureKrakenClientInfrastructureByteArrayWrapper : kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> =  // kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.exportHealthOne(fromHcpId, toHcpId, patId, date, ref, ioIcureKrakenClientInfrastructureByteArrayWrapper)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BeresultexportApi#exportHealthOne")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BeresultexportApi#exportHealthOne")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fromHcpId** | **kotlin.String**|  |
 **toHcpId** | **kotlin.String**|  |
 **patId** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **ref** | **kotlin.String**|  |
 **ioIcureKrakenClientInfrastructureByteArrayWrapper** | [**kotlin.collections.List&lt;io.icure.kraken.client.infrastructure.ByteArrayWrapper&gt;**](io.icure.kraken.client.infrastructure.ByteArrayWrapper.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="exportKmehrReport"></a>
# **exportKmehrReport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; exportKmehrReport(fromHcpId, toHcpId, patId, date, ref, ioIcureKrakenClientInfrastructureByteArrayWrapper, mimeType)

Export data

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BeresultexportApi()
val fromHcpId : kotlin.String = fromHcpId_example // kotlin.String | 
val toHcpId : kotlin.String = toHcpId_example // kotlin.String | 
val patId : kotlin.String = patId_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val ref : kotlin.String = ref_example // kotlin.String | 
val ioIcureKrakenClientInfrastructureByteArrayWrapper : kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> =  // kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> | 
val mimeType : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.exportKmehrReport(fromHcpId, toHcpId, patId, date, ref, ioIcureKrakenClientInfrastructureByteArrayWrapper, mimeType)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BeresultexportApi#exportKmehrReport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BeresultexportApi#exportKmehrReport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fromHcpId** | **kotlin.String**|  |
 **toHcpId** | **kotlin.String**|  |
 **patId** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **ref** | **kotlin.String**|  |
 **ioIcureKrakenClientInfrastructureByteArrayWrapper** | [**kotlin.collections.List&lt;io.icure.kraken.client.infrastructure.ByteArrayWrapper&gt;**](io.icure.kraken.client.infrastructure.ByteArrayWrapper.md)|  |
 **mimeType** | **kotlin.Boolean**|  | [optional]

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="exportMedidoc"></a>
# **exportMedidoc**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; exportMedidoc(fromHcpId, toHcpId, patId, date, ref, ioIcureKrakenClientInfrastructureByteArrayWrapper)

Export data

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BeresultexportApi()
val fromHcpId : kotlin.String = fromHcpId_example // kotlin.String | 
val toHcpId : kotlin.String = toHcpId_example // kotlin.String | 
val patId : kotlin.String = patId_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val ref : kotlin.String = ref_example // kotlin.String | 
val ioIcureKrakenClientInfrastructureByteArrayWrapper : kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> =  // kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.exportMedidoc(fromHcpId, toHcpId, patId, date, ref, ioIcureKrakenClientInfrastructureByteArrayWrapper)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BeresultexportApi#exportMedidoc")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BeresultexportApi#exportMedidoc")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fromHcpId** | **kotlin.String**|  |
 **toHcpId** | **kotlin.String**|  |
 **patId** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **ref** | **kotlin.String**|  |
 **ioIcureKrakenClientInfrastructureByteArrayWrapper** | [**kotlin.collections.List&lt;io.icure.kraken.client.infrastructure.ByteArrayWrapper&gt;**](io.icure.kraken.client.infrastructure.ByteArrayWrapper.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

