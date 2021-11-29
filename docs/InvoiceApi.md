# InvoiceApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**appendCodes**](InvoiceApi.md#appendCodes) | **POST** /rest/v1/invoice/byauthor/{userId}/append/{type}/{sentMediumType} | Gets all invoices for author at date
[**createInvoice**](InvoiceApi.md#createInvoice) | **POST** /rest/v1/invoice | Creates an invoice
[**createInvoices**](InvoiceApi.md#createInvoices) | **POST** /rest/v1/invoice/batch | Create a batch of invoices
[**deleteInvoice**](InvoiceApi.md#deleteInvoice) | **DELETE** /rest/v1/invoice/{invoiceId} | Deletes an invoice
[**filterInvoicesBy**](InvoiceApi.md#filterInvoicesBy) | **POST** /rest/v1/invoice/filter | Filter invoices for the current user (HcParty)
[**findByAuthor**](InvoiceApi.md#findByAuthor) | **GET** /rest/v1/invoice/byauthor/{hcPartyId} | Gets all invoices for author at date
[**findInvoicesByHCPartyPatientForeignKeys**](InvoiceApi.md#findInvoicesByHCPartyPatientForeignKeys) | **GET** /rest/v1/invoice/byHcPartySecretForeignKeys | List invoices found By Healthcare Party and secret foreign patient keys.
[**findInvoicesDelegationsStubsByHCPartyPatientForeignKeys**](InvoiceApi.md#findInvoicesDelegationsStubsByHCPartyPatientForeignKeys) | **GET** /rest/v1/invoice/byHcPartySecretForeignKeys/delegations | List helement stubs found By Healthcare Party and secret foreign keys.
[**getInvoice**](InvoiceApi.md#getInvoice) | **GET** /rest/v1/invoice/{invoiceId} | Gets an invoice
[**getInvoices**](InvoiceApi.md#getInvoices) | **POST** /rest/v1/invoice/byIds | Gets an invoice
[**getTarificationsCodesOccurences**](InvoiceApi.md#getTarificationsCodesOccurences) | **GET** /rest/v1/invoice/codes/{minOccurences} | Get the list of all used tarifications frequencies in invoices
[**listAllHcpsByStatus**](InvoiceApi.md#listAllHcpsByStatus) | **POST** /rest/v1/invoice/allHcpsByStatus/{status} | Gets all invoices per status
[**listByContactIds**](InvoiceApi.md#listByContactIds) | **POST** /rest/v1/invoice/byCtcts | Gets all invoices for author at date
[**listByHcPartyGroupId**](InvoiceApi.md#listByHcPartyGroupId) | **GET** /rest/v1/invoice/byHcPartyGroupId/{hcPartyId}/{groupId} | List invoices by groupId
[**listByHcPartySentMediumTypeInvoiceTypeSentDate**](InvoiceApi.md#listByHcPartySentMediumTypeInvoiceTypeSentDate) | **GET** /rest/v1/invoice/byHcParty/{hcPartyId}/mediumType/{sentMediumType}/invoiceType/{invoiceType}/sent/{sent} | List invoices by type, sent or unsent
[**listByHcpartySendingModeStatusDate**](InvoiceApi.md#listByHcpartySendingModeStatusDate) | **GET** /rest/v1/invoice/byHcpartySendingModeStatusDate/{hcPartyId} | Get all invoices by author, by sending mode, by status and by date
[**listByIds**](InvoiceApi.md#listByIds) | **GET** /rest/v1/invoice/byIds/{invoiceIds} | Gets all invoices for author at date
[**listByRecipientsIds**](InvoiceApi.md#listByRecipientsIds) | **GET** /rest/v1/invoice/to/{recipientIds} | Gets all invoices for author at date
[**listByServiceIds**](InvoiceApi.md#listByServiceIds) | **GET** /rest/v1/invoice/byServiceIds/{serviceIds} | Gets all invoices for author at date
[**listToInsurances**](InvoiceApi.md#listToInsurances) | **GET** /rest/v1/invoice/toInsurances | Gets all invoices for author at date
[**listToInsurancesUnsent**](InvoiceApi.md#listToInsurancesUnsent) | **GET** /rest/v1/invoice/toInsurances/unsent | Gets all invoices for author at date
[**listToPatients**](InvoiceApi.md#listToPatients) | **GET** /rest/v1/invoice/toPatients | Gets all invoices for author at date
[**listToPatientsUnsent**](InvoiceApi.md#listToPatientsUnsent) | **GET** /rest/v1/invoice/toPatients/unsent | Gets all invoices for author at date
[**mergeTo**](InvoiceApi.md#mergeTo) | **POST** /rest/v1/invoice/mergeTo/{invoiceId} | Gets all invoices for author at date
[**modifyInvoice**](InvoiceApi.md#modifyInvoice) | **PUT** /rest/v1/invoice | Modifies an invoice
[**modifyInvoices**](InvoiceApi.md#modifyInvoices) | **PUT** /rest/v1/invoice/batch | Modify a batch of invoices
[**newInvoiceDelegations**](InvoiceApi.md#newInvoiceDelegations) | **PUT** /rest/v1/invoice/{invoiceId}/delegate | Adds a delegation to a invoice
[**reassignInvoice**](InvoiceApi.md#reassignInvoice) | **POST** /rest/v1/invoice/reassign | Modifies an invoice
[**removeCodes**](InvoiceApi.md#removeCodes) | **POST** /rest/v1/invoice/byauthor/{userId}/service/{serviceId} | Gets all invoices for author at date
[**setInvoicesDelegations**](InvoiceApi.md#setInvoicesDelegations) | **POST** /rest/v1/invoice/delegations | Update delegations in healthElements.
[**validate**](InvoiceApi.md#validate) | **POST** /rest/v1/invoice/validate/{invoiceId} | Gets all invoices for author at date


<a name="appendCodes"></a>
# **appendCodes**
> kotlin.collections.List&lt;InvoiceDto&gt; appendCodes(userId, type, sentMediumType, secretFKeys, invoicingCodeDto, insuranceId, invoiceId, gracePeriod)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val type : kotlin.String = type_example // kotlin.String | 
val sentMediumType : kotlin.String = sentMediumType_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
val invoicingCodeDto : kotlin.collections.List<InvoicingCodeDto> =  // kotlin.collections.List<InvoicingCodeDto> | 
val insuranceId : kotlin.String = insuranceId_example // kotlin.String | 
val invoiceId : kotlin.String = invoiceId_example // kotlin.String | 
val gracePeriod : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.appendCodes(userId, type, sentMediumType, secretFKeys, invoicingCodeDto, insuranceId, invoiceId, gracePeriod)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#appendCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#appendCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **type** | **kotlin.String**|  |
 **sentMediumType** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |
 **invoicingCodeDto** | [**kotlin.collections.List&lt;InvoicingCodeDto&gt;**](InvoicingCodeDto.md)|  |
 **insuranceId** | **kotlin.String**|  | [optional]
 **invoiceId** | **kotlin.String**|  | [optional]
 **gracePeriod** | **kotlin.Int**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createInvoice"></a>
# **createInvoice**
> InvoiceDto createInvoice(invoiceDto)

Creates an invoice

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceDto : InvoiceDto =  // InvoiceDto | 
try {
    val result : InvoiceDto = apiInstance.createInvoice(invoiceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#createInvoice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#createInvoice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceDto** | [**InvoiceDto**](InvoiceDto.md)|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createInvoices"></a>
# **createInvoices**
> kotlin.collections.List&lt;InvoiceDto&gt; createInvoices(invoiceDto)

Create a batch of invoices

Returns the created invoices.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceDto : kotlin.collections.List<InvoiceDto> =  // kotlin.collections.List<InvoiceDto> | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.createInvoices(invoiceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#createInvoices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#createInvoices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceDto** | [**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteInvoice"></a>
# **deleteInvoice**
> DocIdentifier deleteInvoice(invoiceId)

Deletes an invoice

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceId : kotlin.String = invoiceId_example // kotlin.String | 
try {
    val result : DocIdentifier = apiInstance.deleteInvoice(invoiceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#deleteInvoice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#deleteInvoice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceId** | **kotlin.String**|  |

### Return type

[**DocIdentifier**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="filterInvoicesBy"></a>
# **filterInvoicesBy**
> kotlin.collections.List&lt;InvoiceDto&gt; filterInvoicesBy(filterChainInvoice)

Filter invoices for the current user (HcParty)

Returns a list of invoices along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val filterChainInvoice : FilterChainInvoice =  // FilterChainInvoice | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.filterInvoicesBy(filterChainInvoice)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#filterInvoicesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#filterInvoicesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterChainInvoice** | [**FilterChainInvoice**](FilterChainInvoice.md)|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findByAuthor"></a>
# **findByAuthor**
> PaginatedListInvoiceDto findByAuthor(hcPartyId, fromDate, toDate, startKey, startDocumentId, limit)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val fromDate : kotlin.Long = 789 // kotlin.Long | 
val toDate : kotlin.Long = 789 // kotlin.Long | 
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListInvoiceDto = apiInstance.findByAuthor(hcPartyId, fromDate, toDate, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#findByAuthor")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#findByAuthor")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **fromDate** | **kotlin.Long**|  | [optional]
 **toDate** | **kotlin.Long**|  | [optional]
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListInvoiceDto**](PaginatedListInvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findInvoicesByHCPartyPatientForeignKeys"></a>
# **findInvoicesByHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;InvoiceDto&gt; findInvoicesByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)

List invoices found By Healthcare Party and secret foreign patient keys.

Keys have to delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.findInvoicesByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#findInvoicesByHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#findInvoicesByHCPartyPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findInvoicesDelegationsStubsByHCPartyPatientForeignKeys"></a>
# **findInvoicesDelegationsStubsByHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;IcureStubDto&gt; findInvoicesDelegationsStubsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)

List helement stubs found By Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.findInvoicesDelegationsStubsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#findInvoicesDelegationsStubsByHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#findInvoicesDelegationsStubsByHCPartyPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;IcureStubDto&gt;**](IcureStubDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getInvoice"></a>
# **getInvoice**
> InvoiceDto getInvoice(invoiceId)

Gets an invoice

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceId : kotlin.String = invoiceId_example // kotlin.String | 
try {
    val result : InvoiceDto = apiInstance.getInvoice(invoiceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#getInvoice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#getInvoice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceId** | **kotlin.String**|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getInvoices"></a>
# **getInvoices**
> kotlin.collections.List&lt;InvoiceDto&gt; getInvoices(listOfIdsDto)

Gets an invoice

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.getInvoices(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#getInvoices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#getInvoices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getTarificationsCodesOccurences"></a>
# **getTarificationsCodesOccurences**
> kotlin.collections.List&lt;LabelledOccurenceDto&gt; getTarificationsCodesOccurences(minOccurences)

Get the list of all used tarifications frequencies in invoices

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val minOccurences : kotlin.Long = 789 // kotlin.Long | 
try {
    val result : kotlin.collections.List<LabelledOccurenceDto> = apiInstance.getTarificationsCodesOccurences(minOccurences)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#getTarificationsCodesOccurences")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#getTarificationsCodesOccurences")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **minOccurences** | **kotlin.Long**|  |

### Return type

[**kotlin.collections.List&lt;LabelledOccurenceDto&gt;**](LabelledOccurenceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listAllHcpsByStatus"></a>
# **listAllHcpsByStatus**
> kotlin.collections.List&lt;InvoiceDto&gt; listAllHcpsByStatus(status, listOfIdsDto, from, to)

Gets all invoices per status

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val status : kotlin.String = status_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
val from : kotlin.Long = 789 // kotlin.Long | 
val to : kotlin.Long = 789 // kotlin.Long | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listAllHcpsByStatus(status, listOfIdsDto, from, to)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listAllHcpsByStatus")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listAllHcpsByStatus")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **status** | **kotlin.String**|  |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |
 **from** | **kotlin.Long**|  | [optional]
 **to** | **kotlin.Long**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listByContactIds"></a>
# **listByContactIds**
> kotlin.collections.List&lt;InvoiceDto&gt; listByContactIds(listOfIdsDto)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listByContactIds(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listByContactIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listByContactIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listByHcPartyGroupId"></a>
# **listByHcPartyGroupId**
> kotlin.collections.List&lt;InvoiceDto&gt; listByHcPartyGroupId(hcPartyId, groupId)

List invoices by groupId

Keys have to delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val groupId : kotlin.String = groupId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listByHcPartyGroupId(hcPartyId, groupId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listByHcPartyGroupId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listByHcPartyGroupId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **groupId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listByHcPartySentMediumTypeInvoiceTypeSentDate"></a>
# **listByHcPartySentMediumTypeInvoiceTypeSentDate**
> kotlin.collections.List&lt;InvoiceDto&gt; listByHcPartySentMediumTypeInvoiceTypeSentDate(hcPartyId, sentMediumType, invoiceType, sent, from, to)

List invoices by type, sent or unsent

Keys have to delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val sentMediumType : kotlin.String = sentMediumType_example // kotlin.String | 
val invoiceType : kotlin.String = invoiceType_example // kotlin.String | 
val sent : kotlin.Boolean = true // kotlin.Boolean | 
val from : kotlin.Long = 789 // kotlin.Long | 
val to : kotlin.Long = 789 // kotlin.Long | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listByHcPartySentMediumTypeInvoiceTypeSentDate(hcPartyId, sentMediumType, invoiceType, sent, from, to)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listByHcPartySentMediumTypeInvoiceTypeSentDate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listByHcPartySentMediumTypeInvoiceTypeSentDate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **sentMediumType** | **kotlin.String**|  | [enum: cdrom, eattest, efact, email, mediprima, paper, stat]
 **invoiceType** | **kotlin.String**|  | [enum: patient, mutualfund, payingagency, insurance, efact, other]
 **sent** | **kotlin.Boolean**|  |
 **from** | **kotlin.Long**|  | [optional]
 **to** | **kotlin.Long**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listByHcpartySendingModeStatusDate"></a>
# **listByHcpartySendingModeStatusDate**
> kotlin.collections.List&lt;InvoiceDto&gt; listByHcpartySendingModeStatusDate(hcPartyId, sendingMode, status, from, to)

Get all invoices by author, by sending mode, by status and by date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val sendingMode : kotlin.String = sendingMode_example // kotlin.String | 
val status : kotlin.String = status_example // kotlin.String | 
val from : kotlin.Long = 789 // kotlin.Long | 
val to : kotlin.Long = 789 // kotlin.Long | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listByHcpartySendingModeStatusDate(hcPartyId, sendingMode, status, from, to)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listByHcpartySendingModeStatusDate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listByHcpartySendingModeStatusDate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **sendingMode** | **kotlin.String**|  | [optional]
 **status** | **kotlin.String**|  | [optional]
 **from** | **kotlin.Long**|  | [optional]
 **to** | **kotlin.Long**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listByIds"></a>
# **listByIds**
> kotlin.collections.List&lt;InvoiceDto&gt; listByIds(invoiceIds)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceIds : kotlin.String = invoiceIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listByIds(invoiceIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listByIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listByIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listByRecipientsIds"></a>
# **listByRecipientsIds**
> kotlin.collections.List&lt;InvoiceDto&gt; listByRecipientsIds(recipientIds)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val recipientIds : kotlin.String = recipientIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listByRecipientsIds(recipientIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listByRecipientsIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listByRecipientsIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **recipientIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listByServiceIds"></a>
# **listByServiceIds**
> kotlin.collections.List&lt;InvoiceDto&gt; listByServiceIds(serviceIds)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val serviceIds : kotlin.String = serviceIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listByServiceIds(serviceIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listByServiceIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listByServiceIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **serviceIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listToInsurances"></a>
# **listToInsurances**
> kotlin.collections.List&lt;InvoiceDto&gt; listToInsurances(userIds)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val userIds : kotlin.String = userIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listToInsurances(userIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listToInsurances")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listToInsurances")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userIds** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listToInsurancesUnsent"></a>
# **listToInsurancesUnsent**
> kotlin.collections.List&lt;InvoiceDto&gt; listToInsurancesUnsent(userIds)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val userIds : kotlin.String = userIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listToInsurancesUnsent(userIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listToInsurancesUnsent")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listToInsurancesUnsent")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userIds** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listToPatients"></a>
# **listToPatients**
> kotlin.collections.List&lt;InvoiceDto&gt; listToPatients(hcPartyId)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listToPatients(hcPartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listToPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listToPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listToPatientsUnsent"></a>
# **listToPatientsUnsent**
> kotlin.collections.List&lt;InvoiceDto&gt; listToPatientsUnsent(hcPartyId)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.listToPatientsUnsent(hcPartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#listToPatientsUnsent")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#listToPatientsUnsent")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="mergeTo"></a>
# **mergeTo**
> InvoiceDto mergeTo(invoiceId, listOfIdsDto)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceId : kotlin.String = invoiceId_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : InvoiceDto = apiInstance.mergeTo(invoiceId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#mergeTo")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#mergeTo")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceId** | **kotlin.String**|  |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyInvoice"></a>
# **modifyInvoice**
> InvoiceDto modifyInvoice(invoiceDto)

Modifies an invoice

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceDto : InvoiceDto =  // InvoiceDto | 
try {
    val result : InvoiceDto = apiInstance.modifyInvoice(invoiceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#modifyInvoice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#modifyInvoice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceDto** | [**InvoiceDto**](InvoiceDto.md)|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyInvoices"></a>
# **modifyInvoices**
> kotlin.collections.List&lt;InvoiceDto&gt; modifyInvoices(invoiceDto)

Modify a batch of invoices

Returns the modified invoices.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceDto : kotlin.collections.List<InvoiceDto> =  // kotlin.collections.List<InvoiceDto> | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.modifyInvoices(invoiceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#modifyInvoices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#modifyInvoices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceDto** | [**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="newInvoiceDelegations"></a>
# **newInvoiceDelegations**
> InvoiceDto newInvoiceDelegations(invoiceId, delegationDto)

Adds a delegation to a invoice

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceId : kotlin.String = invoiceId_example // kotlin.String | 
val delegationDto : kotlin.collections.List<DelegationDto> =  // kotlin.collections.List<DelegationDto> | 
try {
    val result : InvoiceDto = apiInstance.newInvoiceDelegations(invoiceId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#newInvoiceDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#newInvoiceDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceId** | **kotlin.String**|  |
 **delegationDto** | [**kotlin.collections.List&lt;DelegationDto&gt;**](DelegationDto.md)|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="reassignInvoice"></a>
# **reassignInvoice**
> InvoiceDto reassignInvoice(invoiceDto)

Modifies an invoice

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceDto : InvoiceDto =  // InvoiceDto | 
try {
    val result : InvoiceDto = apiInstance.reassignInvoice(invoiceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#reassignInvoice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#reassignInvoice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceDto** | [**InvoiceDto**](InvoiceDto.md)|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="removeCodes"></a>
# **removeCodes**
> kotlin.collections.List&lt;InvoiceDto&gt; removeCodes(userId, serviceId, secretFKeys, requestBody)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val serviceId : kotlin.String = serviceId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.removeCodes(userId, serviceId, secretFKeys, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#removeCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#removeCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **serviceId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setInvoicesDelegations"></a>
# **setInvoicesDelegations**
> kotlin.collections.List&lt;IcureStubDto&gt; setInvoicesDelegations(icureStubDto)

Update delegations in healthElements.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val icureStubDto : kotlin.collections.List<IcureStubDto> =  // kotlin.collections.List<IcureStubDto> | 
try {
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.setInvoicesDelegations(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#setInvoicesDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#setInvoicesDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **icureStubDto** | [**kotlin.collections.List&lt;IcureStubDto&gt;**](IcureStubDto.md)|  |

### Return type

[**kotlin.collections.List&lt;IcureStubDto&gt;**](IcureStubDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="validate"></a>
# **validate**
> InvoiceDto validate(invoiceId, scheme, forcedValue)

Gets all invoices for author at date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = InvoiceApi()
val invoiceId : kotlin.String = invoiceId_example // kotlin.String | 
val scheme : kotlin.String = scheme_example // kotlin.String | 
val forcedValue : kotlin.String = forcedValue_example // kotlin.String | 
try {
    val result : InvoiceDto = apiInstance.validate(invoiceId, scheme, forcedValue)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling InvoiceApi#validate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling InvoiceApi#validate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceId** | **kotlin.String**|  |
 **scheme** | **kotlin.String**|  |
 **forcedValue** | **kotlin.String**|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

