# MessageApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createMessage**](MessageApi.md#createMessage) | **POST** /rest/v2/message | Creates a message
[**createMessage1**](MessageApi.md#createMessage1) | **POST** /rest/v1/message | Creates a message
[**deleteDelegation**](MessageApi.md#deleteDelegation) | **DELETE** /rest/v2/message/{messageId}/delegate/{delegateId} | Deletes a message delegation
[**deleteDelegation1**](MessageApi.md#deleteDelegation1) | **DELETE** /rest/v1/message/{messageId}/delegate/{delegateId} | Deletes a message delegation
[**deleteMessages**](MessageApi.md#deleteMessages) | **POST** /rest/v2/message/delete/batch | Deletes multiple messages
[**deleteMessages1**](MessageApi.md#deleteMessages1) | **DELETE** /rest/v1/message/{messageIds} | Deletes multiple messages
[**deleteMessagesBatch**](MessageApi.md#deleteMessagesBatch) | **POST** /rest/v1/message/delete/byIds | Deletes multiple messages
[**findMessages**](MessageApi.md#findMessages) | **GET** /rest/v2/message | Get all messages (paginated) for current HC Party
[**findMessages1**](MessageApi.md#findMessages1) | **GET** /rest/v1/message | Get all messages (paginated) for current HC Party
[**findMessagesByFromAddress**](MessageApi.md#findMessagesByFromAddress) | **GET** /rest/v2/message/byFromAddress | Get all messages (paginated) for current HC Party and provided from address
[**findMessagesByFromAddress1**](MessageApi.md#findMessagesByFromAddress1) | **GET** /rest/v1/message/byFromAddress | Get all messages (paginated) for current HC Party and provided from address
[**findMessagesByHCPartyPatientForeignKeys**](MessageApi.md#findMessagesByHCPartyPatientForeignKeys) | **GET** /rest/v2/message/byHcPartySecretForeignKeys | List messages found By Healthcare Party and secret foreign keys.
[**findMessagesByHCPartyPatientForeignKeys1**](MessageApi.md#findMessagesByHCPartyPatientForeignKeys1) | **GET** /rest/v1/message/byHcPartySecretForeignKeys | List messages found By Healthcare Party and secret foreign keys.
[**findMessagesByToAddress**](MessageApi.md#findMessagesByToAddress) | **GET** /rest/v2/message/byToAddress | Get all messages (paginated) for current HC Party and provided to address
[**findMessagesByToAddress1**](MessageApi.md#findMessagesByToAddress1) | **GET** /rest/v1/message/byToAddress | Get all messages (paginated) for current HC Party and provided to address
[**findMessagesByTransportGuid**](MessageApi.md#findMessagesByTransportGuid) | **GET** /rest/v2/message/byTransportGuid | Get all messages (paginated) for current HC Party and provided transportGuid
[**findMessagesByTransportGuid1**](MessageApi.md#findMessagesByTransportGuid1) | **GET** /rest/v1/message/byTransportGuid | Get all messages (paginated) for current HC Party and provided transportGuid
[**findMessagesByTransportGuidSentDate**](MessageApi.md#findMessagesByTransportGuidSentDate) | **GET** /rest/v2/message/byTransportGuidSentDate | Get all messages starting by a prefix between two date
[**findMessagesByTransportGuidSentDate1**](MessageApi.md#findMessagesByTransportGuidSentDate1) | **GET** /rest/v1/message/byTransportGuidSentDate | Get all messages starting by a prefix between two date
[**getChildrenMessages**](MessageApi.md#getChildrenMessages) | **GET** /rest/v2/message/{messageId}/children | Get children messages of provided message
[**getChildrenMessages1**](MessageApi.md#getChildrenMessages1) | **GET** /rest/v1/message/{messageId}/children | Get children messages of provided message
[**getChildrenMessagesOfList**](MessageApi.md#getChildrenMessagesOfList) | **POST** /rest/v1/message/children/batch | Get children messages of provided message
[**getMessage**](MessageApi.md#getMessage) | **GET** /rest/v2/message/{messageId} | Gets a message
[**getMessage1**](MessageApi.md#getMessage1) | **GET** /rest/v1/message/{messageId} | Gets a message
[**getMessagesChildren**](MessageApi.md#getMessagesChildren) | **POST** /rest/v2/message/children/batch | Get children messages of provided message
[**listMessagesByInvoiceIds**](MessageApi.md#listMessagesByInvoiceIds) | **POST** /rest/v1/message/byInvoiceId | Get children messages of provided message
[**listMessagesByInvoices**](MessageApi.md#listMessagesByInvoices) | **POST** /rest/v2/message/byInvoice | Get children messages of provided message
[**listMessagesByTransportGuids**](MessageApi.md#listMessagesByTransportGuids) | **POST** /rest/v2/message/byTransportGuid/list | Get all messages for current HC Party and provided transportGuids
[**listMessagesByTransportGuids1**](MessageApi.md#listMessagesByTransportGuids1) | **POST** /rest/v1/message/byTransportGuid/list | Get all messages for current HC Party and provided transportGuids
[**modifyMessage**](MessageApi.md#modifyMessage) | **PUT** /rest/v2/message | Updates a message
[**modifyMessage1**](MessageApi.md#modifyMessage1) | **PUT** /rest/v1/message | Updates a message
[**newMessageDelegations**](MessageApi.md#newMessageDelegations) | **PUT** /rest/v2/message/{messageId}/delegate | Adds a delegation to a message
[**newMessageDelegations1**](MessageApi.md#newMessageDelegations1) | **PUT** /rest/v1/message/{messageId}/delegate | Adds a delegation to a message
[**setMessagesReadStatus**](MessageApi.md#setMessagesReadStatus) | **PUT** /rest/v2/message/readstatus | Set read status for given list of messages
[**setMessagesReadStatus1**](MessageApi.md#setMessagesReadStatus1) | **PUT** /rest/v1/message/readstatus | Set read status for given list of messages
[**setMessagesStatusBits**](MessageApi.md#setMessagesStatusBits) | **PUT** /rest/v2/message/status/{status} | Set status bits for given list of messages
[**setMessagesStatusBits1**](MessageApi.md#setMessagesStatusBits1) | **PUT** /rest/v1/message/status/{status} | Set status bits for given list of messages


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

<a name="createMessage1"></a>
# **createMessage1**
> MessageDto createMessage1(messageDto)

Creates a message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageDto : MessageDto =  // MessageDto | 
try {
    val result : MessageDto = apiInstance.createMessage1(messageDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#createMessage1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#createMessage1")
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

<a name="deleteDelegation1"></a>
# **deleteDelegation1**
> MessageDto deleteDelegation1(messageId, delegateId)

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
    val result : MessageDto = apiInstance.deleteDelegation1(messageId, delegateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#deleteDelegation1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#deleteDelegation1")
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

<a name="deleteMessages1"></a>
# **deleteMessages1**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteMessages1(messageIds)

Deletes multiple messages

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageIds : kotlin.String = messageIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteMessages1(messageIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#deleteMessages1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#deleteMessages1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deleteMessagesBatch"></a>
# **deleteMessagesBatch**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteMessagesBatch(listOfIdsDto)

Deletes multiple messages

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteMessagesBatch(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#deleteMessagesBatch")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#deleteMessagesBatch")
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

<a name="findMessages1"></a>
# **findMessages1**
> PaginatedListMessageDto findMessages1(startKey, startDocumentId, limit)

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
    val result : PaginatedListMessageDto = apiInstance.findMessages1(startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessages1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessages1")
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

<a name="findMessagesByFromAddress1"></a>
# **findMessagesByFromAddress1**
> PaginatedListMessageDto findMessagesByFromAddress1(fromAddress, startKey, startDocumentId, limit, hcpId)

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
    val result : PaginatedListMessageDto = apiInstance.findMessagesByFromAddress1(fromAddress, startKey, startDocumentId, limit, hcpId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByFromAddress1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByFromAddress1")
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

<a name="findMessagesByHCPartyPatientForeignKeys1"></a>
# **findMessagesByHCPartyPatientForeignKeys1**
> kotlin.collections.List&lt;MessageDto&gt; findMessagesByHCPartyPatientForeignKeys1(secretFKeys)

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
    val result : kotlin.collections.List<MessageDto> = apiInstance.findMessagesByHCPartyPatientForeignKeys1(secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByHCPartyPatientForeignKeys1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByHCPartyPatientForeignKeys1")
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

<a name="findMessagesByToAddress1"></a>
# **findMessagesByToAddress1**
> PaginatedListMessageDto findMessagesByToAddress1(toAddress, startKey, startDocumentId, limit, reverse, hcpId)

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
    val result : PaginatedListMessageDto = apiInstance.findMessagesByToAddress1(toAddress, startKey, startDocumentId, limit, reverse, hcpId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByToAddress1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByToAddress1")
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

<a name="findMessagesByTransportGuid1"></a>
# **findMessagesByTransportGuid1**
> PaginatedListMessageDto findMessagesByTransportGuid1(transportGuid, received, startKey, startDocumentId, limit, hcpId)

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
    val result : PaginatedListMessageDto = apiInstance.findMessagesByTransportGuid1(transportGuid, received, startKey, startDocumentId, limit, hcpId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByTransportGuid1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByTransportGuid1")
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
> PaginatedListMessageDto findMessagesByTransportGuidSentDate(from, to, transportGuid, startKey, startDocumentId, limit, hcpId)

Get all messages starting by a prefix between two date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val from : kotlin.Long = 789 // kotlin.Long | 
val to : kotlin.Long = 789 // kotlin.Long | 
val transportGuid : kotlin.String = transportGuid_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
try {
    val result : PaginatedListMessageDto = apiInstance.findMessagesByTransportGuidSentDate(from, to, transportGuid, startKey, startDocumentId, limit, hcpId)
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
 **from** | **kotlin.Long**|  | [optional]
 **to** | **kotlin.Long**|  | [optional]
 **transportGuid** | **kotlin.String**|  | [optional]
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

<a name="findMessagesByTransportGuidSentDate1"></a>
# **findMessagesByTransportGuidSentDate1**
> PaginatedListMessageDto findMessagesByTransportGuidSentDate1(from, to, transportGuid, startKey, startDocumentId, limit, hcpId)

Get all messages starting by a prefix between two date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val from : kotlin.Long = 789 // kotlin.Long | 
val to : kotlin.Long = 789 // kotlin.Long | 
val transportGuid : kotlin.String = transportGuid_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | 
val limit : kotlin.Int = 56 // kotlin.Int | 
val hcpId : kotlin.String = hcpId_example // kotlin.String | 
try {
    val result : PaginatedListMessageDto = apiInstance.findMessagesByTransportGuidSentDate1(from, to, transportGuid, startKey, startDocumentId, limit, hcpId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#findMessagesByTransportGuidSentDate1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#findMessagesByTransportGuidSentDate1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **from** | **kotlin.Long**|  | [optional]
 **to** | **kotlin.Long**|  | [optional]
 **transportGuid** | **kotlin.String**|  | [optional]
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

<a name="getChildrenMessages1"></a>
# **getChildrenMessages1**
> kotlin.collections.List&lt;MessageDto&gt; getChildrenMessages1(messageId)

Get children messages of provided message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageId : kotlin.String = messageId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.getChildrenMessages1(messageId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#getChildrenMessages1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#getChildrenMessages1")
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

<a name="getChildrenMessagesOfList"></a>
# **getChildrenMessagesOfList**
> kotlin.collections.List&lt;MessageDto&gt; getChildrenMessagesOfList(listOfIdsDto)

Get children messages of provided message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.getChildrenMessagesOfList(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#getChildrenMessagesOfList")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#getChildrenMessagesOfList")
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

<a name="getMessage1"></a>
# **getMessage1**
> MessageDto getMessage1(messageId)

Gets a message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageId : kotlin.String = messageId_example // kotlin.String | 
try {
    val result : MessageDto = apiInstance.getMessage1(messageId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#getMessage1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#getMessage1")
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

<a name="listMessagesByInvoiceIds"></a>
# **listMessagesByInvoiceIds**
> kotlin.collections.List&lt;MessageDto&gt; listMessagesByInvoiceIds(listOfIdsDto)

Get children messages of provided message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.listMessagesByInvoiceIds(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#listMessagesByInvoiceIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#listMessagesByInvoiceIds")
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

<a name="listMessagesByTransportGuids1"></a>
# **listMessagesByTransportGuids1**
> kotlin.collections.List&lt;MessageDto&gt; listMessagesByTransportGuids1(hcpId, listOfIdsDto)

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
    val result : kotlin.collections.List<MessageDto> = apiInstance.listMessagesByTransportGuids1(hcpId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#listMessagesByTransportGuids1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#listMessagesByTransportGuids1")
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

<a name="modifyMessage1"></a>
# **modifyMessage1**
> MessageDto modifyMessage1(messageDto)

Updates a message

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messageDto : MessageDto =  // MessageDto | 
try {
    val result : MessageDto = apiInstance.modifyMessage1(messageDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#modifyMessage1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#modifyMessage1")
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

<a name="newMessageDelegations1"></a>
# **newMessageDelegations1**
> IcureStubDto newMessageDelegations1(messageId, delegationDto)

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
    val result : IcureStubDto = apiInstance.newMessageDelegations1(messageId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#newMessageDelegations1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#newMessageDelegations1")
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

<a name="setMessagesReadStatus1"></a>
# **setMessagesReadStatus1**
> kotlin.collections.List&lt;MessageDto&gt; setMessagesReadStatus1(messagesReadStatusUpdate)

Set read status for given list of messages

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = MessageApi()
val messagesReadStatusUpdate : MessagesReadStatusUpdate =  // MessagesReadStatusUpdate | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.setMessagesReadStatus1(messagesReadStatusUpdate)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#setMessagesReadStatus1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#setMessagesReadStatus1")
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

<a name="setMessagesStatusBits1"></a>
# **setMessagesStatusBits1**
> kotlin.collections.List&lt;MessageDto&gt; setMessagesStatusBits1(status, listOfIdsDto)

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
    val result : kotlin.collections.List<MessageDto> = apiInstance.setMessagesStatusBits1(status, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling MessageApi#setMessagesStatusBits1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling MessageApi#setMessagesStatusBits1")
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

