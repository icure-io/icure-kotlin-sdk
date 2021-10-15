# MessageApi

All URIs are relative to *https://kraken.svc.icure.cloud*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createMessage**](MessageApi.md#createMessage) | **POST** /rest/v2/message | Creates a message
[**deleteDelegation**](MessageApi.md#deleteDelegation) | **DELETE** /rest/v2/message/{messageId}/delegate/{delegateId} | Deletes a message delegation
[**deleteMessages**](MessageApi.md#deleteMessages) | **POST** /rest/v2/message/delete/batch | Deletes multiple messages
[**findMessages**](MessageApi.md#findMessages) | **GET** /rest/v2/message | Get all messages (paginated) for current HC Party
[**findMessagesByFromAddress**](MessageApi.md#findMessagesByFromAddress) | **GET** /rest/v2/message/byFromAddress | Get all messages (paginated) for current HC Party and provided from address
[**findMessagesByHCPartyPatientForeignKeys**](MessageApi.md#findMessagesByHCPartyPatientForeignKeys) | **GET** /rest/v2/message/byHcPartySecretForeignKeys | List messages found By Healthcare Party and secret foreign keys.
[**findMessagesByToAddress**](MessageApi.md#findMessagesByToAddress) | **GET** /rest/v2/message/byToAddress | Get all messages (paginated) for current HC Party and provided to address
[**findMessagesByTransportGuid**](MessageApi.md#findMessagesByTransportGuid) | **GET** /rest/v2/message/byTransportGuid | Get all messages (paginated) for current HC Party and provided transportGuid
[**findMessagesByTransportGuidSentDate**](MessageApi.md#findMessagesByTransportGuidSentDate) | **GET** /rest/v2/message/byTransportGuidSentDate | Get all messages starting by a prefix between two date
[**getChildrenMessages**](MessageApi.md#getChildrenMessages) | **GET** /rest/v2/message/{messageId}/children | Get children messages of provided message
[**getMessage**](MessageApi.md#getMessage) | **GET** /rest/v2/message/{messageId} | Gets a message
[**getMessagesChildren**](MessageApi.md#getMessagesChildren) | **POST** /rest/v2/message/children/batch | Get children messages of provided message
[**listMessagesByInvoices**](MessageApi.md#listMessagesByInvoices) | **POST** /rest/v2/message/byInvoice | Get children messages of provided message
[**listMessagesByTransportGuids**](MessageApi.md#listMessagesByTransportGuids) | **POST** /rest/v2/message/byTransportGuid/list | Get all messages for current HC Party and provided transportGuids
[**modifyMessage**](MessageApi.md#modifyMessage) | **PUT** /rest/v2/message | Updates a message
[**newMessageDelegations**](MessageApi.md#newMessageDelegations) | **PUT** /rest/v2/message/{messageId}/delegate | Adds a delegation to a message
[**setMessagesReadStatus**](MessageApi.md#setMessagesReadStatus) | **PUT** /rest/v2/message/readstatus | Set read status for given list of messages
[**setMessagesStatusBits**](MessageApi.md#setMessagesStatusBits) | **PUT** /rest/v2/message/status/{status} | Set status bits for given list of messages


<a name="createMessage"></a>
# **createMessage**
> MessageDto createMessage(messageDto)

Creates a message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageDto : MessageDto =  // MessageDto | 
try {
    val result : MessageDto = apiInstance.createMessage(messageDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#createMessage")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#createMessage")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageDto** | [**MessageDto**](MessageDto.md)|  |

### Return type

[**MessageDto**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteDelegation"></a>
# **deleteDelegation**
> MessageDto deleteDelegation(messageId, delegateId)

Deletes a message delegation

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageId : kotlin.String = messageId_example // kotlin.String | 
val delegateId : kotlin.String = delegateId_example // kotlin.String | 
try {
    val result : MessageDto = apiInstance.deleteDelegation(messageId, delegateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#deleteDelegation")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#deleteDelegation")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageId** | **kotlin.String**|  |
 **delegateId** | **kotlin.String**|  |

### Return type

[**MessageDto**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deleteMessages"></a>
# **deleteMessages**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteMessages(listOfIdsDto)

Deletes multiple messages

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteMessages(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#deleteMessages")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#deleteMessages")
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

<a name="findMessages"></a>
# **findMessages**
> PaginatedListMessageDto findMessages(startKey, startDocumentId, limit)

Get all messages (paginated) for current HC Party

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val startKey : kotlin.String = startKey_example // kotlin.String | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListMessageDto = apiInstance.findMessages(startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessages")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessages")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startKey** | **kotlin.String**|  | [optional]
 **startDocumentId** | **kotlin.String**|  | [optional]
 **limit** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListMessageDto**](PaginatedListMessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findMessagesByFromAddress"></a>
# **findMessagesByFromAddress**
> PaginatedListMessageDto findMessagesByFromAddress(fromAddress, startKey, startDocumentId, limit, hcpId)

Get all messages (paginated) for current HC Party and provided from address

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val fromAddress : kotlin.String = fromAddress_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
try {
    val result : PaginatedListMessageDto = apiInstance.findMessagesByFromAddress(fromAddress, startKey, startDocumentId, limit, hcpId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByFromAddress")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByFromAddress")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fromAddress** | **kotlin.String**|  | [optional]
 **startKey** | **kotlin.String**|  | [optional]
 **startDocumentId** | **kotlin.String**|  | [optional]
 **limit** | **kotlin.Int**|  | [optional]
 **hcpId** | **kotlin.String**|  | [optional]

### Return type

[**PaginatedListMessageDto**](PaginatedListMessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findMessagesByHCPartyPatientForeignKeys"></a>
# **findMessagesByHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;MessageDto&gt; findMessagesByHCPartyPatientForeignKeys(secretFKeys)

List messages found By Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.findMessagesByHCPartyPatientForeignKeys(secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByHCPartyPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findMessagesByToAddress"></a>
# **findMessagesByToAddress**
> PaginatedListMessageDto findMessagesByToAddress(toAddress, startKey, startDocumentId, limit, reverse, hcpId)

Get all messages (paginated) for current HC Party and provided to address

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val toAddress : kotlin.String = toAddress_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
val reverse : kotlin.Boolean = true // kotlin.Boolean | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
try {
    val result : PaginatedListMessageDto = apiInstance.findMessagesByToAddress(toAddress, startKey, startDocumentId, limit, reverse, hcpId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByToAddress")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByToAddress")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **toAddress** | **kotlin.String**|  | [optional]
 **startKey** | **kotlin.String**|  | [optional]
 **startDocumentId** | **kotlin.String**|  | [optional]
 **limit** | **kotlin.Int**|  | [optional]
 **reverse** | **kotlin.Boolean**|  | [optional]
 **hcpId** | **kotlin.String**|  | [optional]

### Return type

[**PaginatedListMessageDto**](PaginatedListMessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findMessagesByTransportGuid"></a>
# **findMessagesByTransportGuid**
> PaginatedListMessageDto findMessagesByTransportGuid(transportGuid, received, startKey, startDocumentId, limit, hcpId)

Get all messages (paginated) for current HC Party and provided transportGuid

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val transportGuid : kotlin.String = transportGuid_example // kotlin.String | 
val received : kotlin.Boolean = true // kotlin.Boolean | 
val startKey : kotlin.String = startKey_example // kotlin.String | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
try {
    val result : PaginatedListMessageDto = apiInstance.findMessagesByTransportGuid(transportGuid, received, startKey, startDocumentId, limit, hcpId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByTransportGuid")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByTransportGuid")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **transportGuid** | **kotlin.String**|  | [optional]
 **received** | **kotlin.Boolean**|  | [optional]
 **startKey** | **kotlin.String**|  | [optional]
 **startDocumentId** | **kotlin.String**|  | [optional]
 **limit** | **kotlin.Int**|  | [optional]
 **hcpId** | **kotlin.String**|  | [optional]

### Return type

[**PaginatedListMessageDto**](PaginatedListMessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findMessagesByTransportGuidSentDate"></a>
# **findMessagesByTransportGuidSentDate**
> PaginatedListMessageDto findMessagesByTransportGuidSentDate(transportGuid, from, to, startKey, startDocumentId, limit, hcpId)

Get all messages starting by a prefix between two date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val transportGuid : kotlin.String = transportGuid_example // kotlin.String | 
val from : kotlin.Long = 789 // kotlin.Long | 
val to : kotlin.Long = 789 // kotlin.Long | 
val startKey : kotlin.String = startKey_example // kotlin.String | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
try {
    val result : PaginatedListMessageDto = apiInstance.findMessagesByTransportGuidSentDate(transportGuid, from, to, startKey, startDocumentId, limit, hcpId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByTransportGuidSentDate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByTransportGuidSentDate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **transportGuid** | **kotlin.String**|  | [optional]
 **from** | **kotlin.Long**|  | [optional]
 **to** | **kotlin.Long**|  | [optional]
 **startKey** | **kotlin.String**|  | [optional]
 **startDocumentId** | **kotlin.String**|  | [optional]
 **limit** | **kotlin.Int**|  | [optional]
 **hcpId** | **kotlin.String**|  | [optional]

### Return type

[**PaginatedListMessageDto**](PaginatedListMessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getChildrenMessages"></a>
# **getChildrenMessages**
> kotlin.collections.List&lt;MessageDto&gt; getChildrenMessages(messageId)

Get children messages of provided message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageId : kotlin.String = messageId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.getChildrenMessages(messageId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#getChildrenMessages")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#getChildrenMessages")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getMessage"></a>
# **getMessage**
> MessageDto getMessage(messageId)

Gets a message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageId : kotlin.String = messageId_example // kotlin.String | 
try {
    val result : MessageDto = apiInstance.getMessage(messageId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#getMessage")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#getMessage")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageId** | **kotlin.String**|  |

### Return type

[**MessageDto**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getMessagesChildren"></a>
# **getMessagesChildren**
> kotlin.collections.List&lt;MessageDto&gt; getMessagesChildren(listOfIdsDto)

Get children messages of provided message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.getMessagesChildren(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#getMessagesChildren")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#getMessagesChildren")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listMessagesByInvoices"></a>
# **listMessagesByInvoices**
> kotlin.collections.List&lt;MessageDto&gt; listMessagesByInvoices(listOfIdsDto)

Get children messages of provided message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.listMessagesByInvoices(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#listMessagesByInvoices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#listMessagesByInvoices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listMessagesByTransportGuids"></a>
# **listMessagesByTransportGuids**
> kotlin.collections.List&lt;MessageDto&gt; listMessagesByTransportGuids(hcpId, listOfIdsDto)

Get all messages for current HC Party and provided transportGuids

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.listMessagesByTransportGuids(hcpId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#listMessagesByTransportGuids")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#listMessagesByTransportGuids")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcpId** | **kotlin.String**|  |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyMessage"></a>
# **modifyMessage**
> MessageDto modifyMessage(messageDto)

Updates a message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageDto : MessageDto =  // MessageDto | 
try {
    val result : MessageDto = apiInstance.modifyMessage(messageDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#modifyMessage")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#modifyMessage")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageDto** | [**MessageDto**](MessageDto.md)|  |

### Return type

[**MessageDto**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="newMessageDelegations"></a>
# **newMessageDelegations**
> IcureStubDto newMessageDelegations(messageId, delegationDto)

Adds a delegation to a message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageId : kotlin.String = messageId_example // kotlin.String | 
val delegationDto : kotlin.collections.List<DelegationDto> =  // kotlin.collections.List<DelegationDto> | 
try {
    val result : IcureStubDto = apiInstance.newMessageDelegations(messageId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#newMessageDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#newMessageDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageId** | **kotlin.String**|  |
 **delegationDto** | [**kotlin.collections.List&lt;DelegationDto&gt;**](DelegationDto.md)|  |

### Return type

[**IcureStubDto**](IcureStubDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setMessagesReadStatus"></a>
# **setMessagesReadStatus**
> kotlin.collections.List&lt;MessageDto&gt; setMessagesReadStatus(messagesReadStatusUpdate)

Set read status for given list of messages

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messagesReadStatusUpdate : MessagesReadStatusUpdate =  // MessagesReadStatusUpdate | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.setMessagesReadStatus(messagesReadStatusUpdate)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#setMessagesReadStatus")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#setMessagesReadStatus")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messagesReadStatusUpdate** | [**MessagesReadStatusUpdate**](MessagesReadStatusUpdate.md)|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setMessagesStatusBits"></a>
# **setMessagesStatusBits**
> kotlin.collections.List&lt;MessageDto&gt; setMessagesStatusBits(status, listOfIdsDto)

Set status bits for given list of messages

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val status : kotlin.Int = 56 // kotlin.Int | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.setMessagesStatusBits(status, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#setMessagesStatusBits")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#setMessagesStatusBits")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **status** | **kotlin.Int**|  |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

