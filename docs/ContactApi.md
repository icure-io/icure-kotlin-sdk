# ContactApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**closeForHCPartyPatientForeignKeys**](ContactApi.md#closeForHCPartyPatientForeignKeys) | **PUT** /rest/v1/contact/byHcPartySecretForeignKeys/close | Close contacts for Healthcare Party and secret foreign keys.
[**createContact**](ContactApi.md#createContact) | **POST** /rest/v1/contact | Create a contact with the current user
[**createContacts**](ContactApi.md#createContacts) | **POST** /rest/v1/contact/batch | Create a batch of contacts
[**deleteContacts**](ContactApi.md#deleteContacts) | **DELETE** /rest/v1/contact/{contactIds} | Delete contacts.
[**filterContactsBy**](ContactApi.md#filterContactsBy) | **POST** /rest/v1/contact/filter | List contacts for the current user (HcParty) or the given hcparty in the filter 
[**filterServicesBy**](ContactApi.md#filterServicesBy) | **POST** /rest/v1/contact/service/filter | List services for the current user (HcParty) or the given hcparty in the filter 
[**findByHCPartyFormId**](ContactApi.md#findByHCPartyFormId) | **GET** /rest/v1/contact/byHcPartyFormId | Get a list of contacts found by Healthcare Party and form&#39;s id.
[**findByHCPartyFormIds**](ContactApi.md#findByHCPartyFormIds) | **POST** /rest/v1/contact/byHcPartyFormIds | Get a list of contacts found by Healthcare Party and form&#39;s ids.
[**findByHCPartyPatientSecretFKeys**](ContactApi.md#findByHCPartyPatientSecretFKeys) | **GET** /rest/v1/contact/byHcPartySecretForeignKeys | Get a list of contacts found by Healthcare Party and secret foreign keys.
[**findByHCPartyServiceId**](ContactApi.md#findByHCPartyServiceId) | **GET** /rest/v1/contact/byHcPartyServiceId | List contacts found By Healthcare Party and service Id.
[**findContactsByExternalId**](ContactApi.md#findContactsByExternalId) | **POST** /rest/v1/contact/byExternalId | List contacts found By externalId.
[**findContactsByHCPartyPatientForeignKeys**](ContactApi.md#findContactsByHCPartyPatientForeignKeys) | **POST** /rest/v1/contact/byHcPartyPatientForeignKeys | Get a list of contacts found by Healthcare Party and Patient foreign keys.
[**findContactsDelegationsStubsByHCPartyPatientForeignKeys**](ContactApi.md#findContactsDelegationsStubsByHCPartyPatientForeignKeys) | **GET** /rest/v1/contact/byHcPartySecretForeignKeys/delegations | List contacts found By Healthcare Party and secret foreign keys.
[**getContact**](ContactApi.md#getContact) | **GET** /rest/v1/contact/{contactId} | Get a contact
[**getContacts**](ContactApi.md#getContacts) | **POST** /rest/v1/contact/byIds | Get contacts by batch
[**getEmptyContent**](ContactApi.md#getEmptyContent) | **GET** /rest/v1/contact/service/content/empty | Get an empty content
[**getServiceCodesOccurences**](ContactApi.md#getServiceCodesOccurences) | **GET** /rest/v1/contact/service/codes/{codeType}/{minOccurences} | Get the list of all used codes frequencies in services
[**listContactsByOpeningDate**](ContactApi.md#listContactsByOpeningDate) | **GET** /rest/v1/contact/byOpeningDate | List contacts bu opening date parties with(out) pagination
[**listServices**](ContactApi.md#listServices) | **POST** /rest/v1/contact/service/byIds | List services with provided ids 
[**listServicesByAssociationId**](ContactApi.md#listServicesByAssociationId) | **GET** /rest/v1/contact/service/associationId | List services by related association id
[**listServicesLinkedTo**](ContactApi.md#listServicesLinkedTo) | **POST** /rest/v1/contact/service/linkedTo | List services linked to provided ids 
[**matchContactsBy**](ContactApi.md#matchContactsBy) | **POST** /rest/v1/contact/match | Get ids of contacts matching the provided filter for the current user (HcParty) 
[**modifyContact**](ContactApi.md#modifyContact) | **PUT** /rest/v1/contact | Modify a contact
[**modifyContacts**](ContactApi.md#modifyContacts) | **PUT** /rest/v1/contact/batch | Modify a batch of contacts
[**newContactDelegations**](ContactApi.md#newContactDelegations) | **POST** /rest/v1/contact/{contactId}/delegate | Delegates a contact to a healthcare party
[**setContactsDelegations**](ContactApi.md#setContactsDelegations) | **POST** /rest/v1/contact/delegations | Update delegations in healthElements.


<a name="closeForHCPartyPatientForeignKeys"></a>
# **closeForHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;ContactDto&gt; closeForHCPartyPatientForeignKeys(hcPartyId, secretFKeys)

Close contacts for Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.closeForHCPartyPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#closeForHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#closeForHCPartyPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="createContact"></a>
# **createContact**
> ContactDto createContact(contactDto)

Create a contact with the current user

Creates a contact with the current user and returns an instance of created contact afterward.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val contactDto : ContactDto =  // ContactDto | 
try {
    val result : ContactDto = apiInstance.createContact(contactDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#createContact")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#createContact")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactDto** | [**ContactDto**](ContactDto.md)|  |

### Return type

[**ContactDto**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createContacts"></a>
# **createContacts**
> kotlin.collections.List&lt;ContactDto&gt; createContacts(contactDto)

Create a batch of contacts

Returns the modified contacts.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val contactDto : kotlin.collections.List<ContactDto> =  // kotlin.collections.List<ContactDto> | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.createContacts(contactDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#createContacts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#createContacts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactDto** | [**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteContacts"></a>
# **deleteContacts**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteContacts(contactIds)

Delete contacts.

Response is a set containing the ID&#39;s of deleted contacts.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val contactIds : kotlin.String = contactIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteContacts(contactIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#deleteContacts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#deleteContacts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="filterContactsBy"></a>
# **filterContactsBy**
> PaginatedListContactDto filterContactsBy(filterChainContact, startDocumentId, limit)

List contacts for the current user (HcParty) or the given hcparty in the filter 

Returns a list of contacts along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val filterChainContact : FilterChainContact =  // FilterChainContact | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A Contact document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListContactDto = apiInstance.filterContactsBy(filterChainContact, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#filterContactsBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#filterContactsBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterChainContact** | [**FilterChainContact**](FilterChainContact.md)|  |
 **startDocumentId** | **kotlin.String**| A Contact document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListContactDto**](PaginatedListContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="filterServicesBy"></a>
# **filterServicesBy**
> PaginatedListServiceDto filterServicesBy(filterChainService, startDocumentId, limit)

List services for the current user (HcParty) or the given hcparty in the filter 

Returns a list of contacts along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val filterChainService : FilterChainService =  // FilterChainService | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A Contact document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListServiceDto = apiInstance.filterServicesBy(filterChainService, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#filterServicesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#filterServicesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterChainService** | [**FilterChainService**](FilterChainService.md)|  |
 **startDocumentId** | **kotlin.String**| A Contact document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListServiceDto**](PaginatedListServiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findByHCPartyFormId"></a>
# **findByHCPartyFormId**
> kotlin.collections.List&lt;ContactDto&gt; findByHCPartyFormId(hcPartyId, formId)

Get a list of contacts found by Healthcare Party and form&#39;s id.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val formId : kotlin.String = formId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.findByHCPartyFormId(hcPartyId, formId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#findByHCPartyFormId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#findByHCPartyFormId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **formId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findByHCPartyFormIds"></a>
# **findByHCPartyFormIds**
> kotlin.collections.List&lt;ContactDto&gt; findByHCPartyFormIds(hcPartyId, listOfIdsDto)

Get a list of contacts found by Healthcare Party and form&#39;s ids.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.findByHCPartyFormIds(hcPartyId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#findByHCPartyFormIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#findByHCPartyFormIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findByHCPartyPatientSecretFKeys"></a>
# **findByHCPartyPatientSecretFKeys**
> kotlin.collections.List&lt;ContactDto&gt; findByHCPartyPatientSecretFKeys(hcPartyId, secretFKeys, planOfActionsIds, skipClosedContacts)

Get a list of contacts found by Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
val planOfActionsIds : kotlin.String = planOfActionsIds_example // kotlin.String | 
val skipClosedContacts : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.findByHCPartyPatientSecretFKeys(hcPartyId, secretFKeys, planOfActionsIds, skipClosedContacts)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#findByHCPartyPatientSecretFKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#findByHCPartyPatientSecretFKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |
 **planOfActionsIds** | **kotlin.String**|  | [optional]
 **skipClosedContacts** | **kotlin.Boolean**|  | [optional]

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findByHCPartyServiceId"></a>
# **findByHCPartyServiceId**
> kotlin.collections.List&lt;ContactDto&gt; findByHCPartyServiceId(hcPartyId, serviceId)

List contacts found By Healthcare Party and service Id.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val serviceId : kotlin.String = serviceId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.findByHCPartyServiceId(hcPartyId, serviceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#findByHCPartyServiceId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#findByHCPartyServiceId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **serviceId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findContactsByExternalId"></a>
# **findContactsByExternalId**
> kotlin.collections.List&lt;ContactDto&gt; findContactsByExternalId(externalId)

List contacts found By externalId.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val externalId : kotlin.String = externalId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.findContactsByExternalId(externalId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#findContactsByExternalId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#findContactsByExternalId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **externalId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findContactsByHCPartyPatientForeignKeys"></a>
# **findContactsByHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;ContactDto&gt; findContactsByHCPartyPatientForeignKeys(hcPartyId, listOfIdsDto)

Get a list of contacts found by Healthcare Party and Patient foreign keys.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.findContactsByHCPartyPatientForeignKeys(hcPartyId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#findContactsByHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#findContactsByHCPartyPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findContactsDelegationsStubsByHCPartyPatientForeignKeys"></a>
# **findContactsDelegationsStubsByHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;IcureStubDto&gt; findContactsDelegationsStubsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)

List contacts found By Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.findContactsDelegationsStubsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#findContactsDelegationsStubsByHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#findContactsDelegationsStubsByHCPartyPatientForeignKeys")
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

<a name="getContact"></a>
# **getContact**
> ContactDto getContact(contactId)

Get a contact

Gets a contact based on its id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val contactId : kotlin.String = contactId_example // kotlin.String | 
try {
    val result : ContactDto = apiInstance.getContact(contactId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#getContact")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#getContact")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactId** | **kotlin.String**|  |

### Return type

[**ContactDto**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getContacts"></a>
# **getContacts**
> kotlin.collections.List&lt;ContactDto&gt; getContacts(listOfIdsDto)

Get contacts by batch

Get a list of contact by ids/keys.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.getContacts(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#getContacts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#getContacts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getEmptyContent"></a>
# **getEmptyContent**
> ContentDto getEmptyContent()

Get an empty content

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
try {
    val result : ContentDto = apiInstance.getEmptyContent()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#getEmptyContent")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#getEmptyContent")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**ContentDto**](ContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getServiceCodesOccurences"></a>
# **getServiceCodesOccurences**
> kotlin.collections.List&lt;LabelledOccurenceDto&gt; getServiceCodesOccurences(codeType, minOccurences)

Get the list of all used codes frequencies in services

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val codeType : kotlin.String = codeType_example // kotlin.String | 
val minOccurences : kotlin.Long = 789 // kotlin.Long | 
try {
    val result : kotlin.collections.List<LabelledOccurenceDto> = apiInstance.getServiceCodesOccurences(codeType, minOccurences)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#getServiceCodesOccurences")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#getServiceCodesOccurences")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **codeType** | **kotlin.String**|  |
 **minOccurences** | **kotlin.Long**|  |

### Return type

[**kotlin.collections.List&lt;LabelledOccurenceDto&gt;**](LabelledOccurenceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listContactsByOpeningDate"></a>
# **listContactsByOpeningDate**
> PaginatedListContactDto listContactsByOpeningDate(startKey, endKey, hcpartyid, startDocumentId, limit)

List contacts bu opening date parties with(out) pagination

Returns a list of contacts.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val startKey : kotlin.Long = 789 // kotlin.Long | The contact openingDate
val endKey : kotlin.Long = 789 // kotlin.Long | The contact max openingDate
val hcpartyid : kotlin.String = hcpartyid_example // kotlin.String | hcpartyid
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A contact party document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListContactDto = apiInstance.listContactsByOpeningDate(startKey, endKey, hcpartyid, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listContactsByOpeningDate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listContactsByOpeningDate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startKey** | **kotlin.Long**| The contact openingDate |
 **endKey** | **kotlin.Long**| The contact max openingDate |
 **hcpartyid** | **kotlin.String**| hcpartyid |
 **startDocumentId** | **kotlin.String**| A contact party document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListContactDto**](PaginatedListContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listServices"></a>
# **listServices**
> kotlin.collections.List&lt;ServiceDto&gt; listServices(listOfIdsDto)

List services with provided ids 

Returns a list of services

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<ServiceDto> = apiInstance.listServices(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listServices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listServices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ServiceDto&gt;**](ServiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listServicesByAssociationId"></a>
# **listServicesByAssociationId**
> kotlin.collections.List&lt;ServiceDto&gt; listServicesByAssociationId(associationId)

List services by related association id

Returns a list of services

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val associationId : kotlin.String = associationId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ServiceDto> = apiInstance.listServicesByAssociationId(associationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listServicesByAssociationId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listServicesByAssociationId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **associationId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ServiceDto&gt;**](ServiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listServicesLinkedTo"></a>
# **listServicesLinkedTo**
> kotlin.collections.List&lt;ServiceDto&gt; listServicesLinkedTo(listOfIdsDto, linkType)

List services linked to provided ids 

Returns a list of services

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
val linkType : kotlin.String = linkType_example // kotlin.String | The type of the link
try {
    val result : kotlin.collections.List<ServiceDto> = apiInstance.listServicesLinkedTo(listOfIdsDto, linkType)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listServicesLinkedTo")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listServicesLinkedTo")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |
 **linkType** | **kotlin.String**| The type of the link | [optional]

### Return type

[**kotlin.collections.List&lt;ServiceDto&gt;**](ServiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="matchContactsBy"></a>
# **matchContactsBy**
> kotlin.collections.List&lt;kotlin.String&gt; matchContactsBy(abstractFilterDtoContact)

Get ids of contacts matching the provided filter for the current user (HcParty) 

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val abstractFilterDtoContact : AbstractFilterDtoContact =  // AbstractFilterDtoContact | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.matchContactsBy(abstractFilterDtoContact)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#matchContactsBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#matchContactsBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **abstractFilterDtoContact** | [**AbstractFilterDtoContact**](AbstractFilterDtoContact.md)|  |

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyContact"></a>
# **modifyContact**
> ContactDto modifyContact(contactDto)

Modify a contact

Returns the modified contact.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val contactDto : ContactDto =  // ContactDto | 
try {
    val result : ContactDto = apiInstance.modifyContact(contactDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#modifyContact")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#modifyContact")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactDto** | [**ContactDto**](ContactDto.md)|  |

### Return type

[**ContactDto**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyContacts"></a>
# **modifyContacts**
> kotlin.collections.List&lt;ContactDto&gt; modifyContacts(contactDto)

Modify a batch of contacts

Returns the modified contacts.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val contactDto : kotlin.collections.List<ContactDto> =  // kotlin.collections.List<ContactDto> | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.modifyContacts(contactDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#modifyContacts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#modifyContacts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactDto** | [**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="newContactDelegations"></a>
# **newContactDelegations**
> ContactDto newContactDelegations(contactId, delegationDto)

Delegates a contact to a healthcare party

It delegates a contact to a healthcare party (By current healthcare party). Returns the contact with new delegations.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val contactId : kotlin.String = contactId_example // kotlin.String | 
val delegationDto : DelegationDto =  // DelegationDto | 
try {
    val result : ContactDto = apiInstance.newContactDelegations(contactId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#newContactDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#newContactDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactId** | **kotlin.String**|  |
 **delegationDto** | [**DelegationDto**](DelegationDto.md)|  |

### Return type

[**ContactDto**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setContactsDelegations"></a>
# **setContactsDelegations**
> kotlin.collections.List&lt;ContactDto&gt; setContactsDelegations(icureStubDto)

Update delegations in healthElements.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val icureStubDto : kotlin.collections.List<IcureStubDto> =  // kotlin.collections.List<IcureStubDto> | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.setContactsDelegations(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#setContactsDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#setContactsDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **icureStubDto** | [**kotlin.collections.List&lt;IcureStubDto&gt;**](IcureStubDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

