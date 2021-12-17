# ContactApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**closeForHCPartyPatientForeignKeys**](ContactApi.md#closeForHCPartyPatientForeignKeys) | **PUT** /rest/v2/contact/byHcPartySecretForeignKeys/close | Close contacts for Healthcare Party and secret foreign keys.
[**createContact**](ContactApi.md#createContact) | **POST** /rest/v2/contact | Create a contact with the current user
[**createContacts**](ContactApi.md#createContacts) | **POST** /rest/v2/contact/batch | Create a batch of contacts
[**deleteContacts**](ContactApi.md#deleteContacts) | **POST** /rest/v2/contact/delete/batch | Delete contacts.
[**filterContactsBy**](ContactApi.md#filterContactsBy) | **POST** /rest/v2/contact/filter | List contacts for the current user (HcParty) or the given hcparty in the filter 
[**filterServicesBy**](ContactApi.md#filterServicesBy) | **POST** /rest/v2/contact/service/filter | List services for the current user (HcParty) or the given hcparty in the filter 
[**findContactsByOpeningDate**](ContactApi.md#findContactsByOpeningDate) | **GET** /rest/v2/contact/byOpeningDate | List contacts by opening date parties with(out) pagination
[**getContact**](ContactApi.md#getContact) | **GET** /rest/v2/contact/{contactId} | Get a contact
[**getContacts**](ContactApi.md#getContacts) | **POST** /rest/v2/contact/byIds | Get contacts
[**getEmptyContent**](ContactApi.md#getEmptyContent) | **GET** /rest/v2/contact/service/content/empty | Get an empty content
[**getServiceByHealthcarepartyAndIdentifier**](ContactApi.md#getServiceByHealthcarepartyAndIdentifier) | **GET** /rest/v2/contact/service/{hcPartyId}/{value} | Get service by identifier
[**getServiceCodesOccurences**](ContactApi.md#getServiceCodesOccurences) | **GET** /rest/v2/contact/service/codes/{codeType}/{minOccurences} | Get the list of all used codes frequencies in services
[**getServices**](ContactApi.md#getServices) | **POST** /rest/v2/contact/service | List services with provided ids 
[**getServicesIdsByHealthcarePartyAndIdentifiers**](ContactApi.md#getServicesIdsByHealthcarePartyAndIdentifiers) | **GET** /rest/v2/contact/services/ids/{hcPartyId}/byIdentifiers | Get services ids by identifiers
[**getServicesLinkedTo**](ContactApi.md#getServicesLinkedTo) | **POST** /rest/v2/contact/service/linkedTo | List services linked to provided ids 
[**listContactByHCPartyServiceId**](ContactApi.md#listContactByHCPartyServiceId) | **GET** /rest/v2/contact/byHcPartyServiceId | List contacts found By Healthcare Party and service Id.
[**listContactsByExternalId**](ContactApi.md#listContactsByExternalId) | **POST** /rest/v2/contact/byExternalId | List contacts found By externalId.
[**listContactsByHCPartyAndFormId**](ContactApi.md#listContactsByHCPartyAndFormId) | **GET** /rest/v2/contact/byHcPartyFormId | List contacts found By Healthcare Party and form Id.
[**listContactsByHCPartyAndFormIds**](ContactApi.md#listContactsByHCPartyAndFormIds) | **POST** /rest/v2/contact/byHcPartyFormIds | List contacts found By Healthcare Party and form Id.
[**listContactsByHCPartyAndPatientForeignKeys**](ContactApi.md#listContactsByHCPartyAndPatientForeignKeys) | **POST** /rest/v2/contact/byHcPartyPatientForeignKeys | List contacts found By Healthcare Party and Patient foreign keys.
[**listContactsByHCPartyAndPatientSecretFKeys**](ContactApi.md#listContactsByHCPartyAndPatientSecretFKeys) | **GET** /rest/v2/contact/byHcPartySecretForeignKeys | List contacts found By Healthcare Party and secret foreign keys.
[**listContactsDelegationsStubsByHCPartyAndPatientForeignKeys**](ContactApi.md#listContactsDelegationsStubsByHCPartyAndPatientForeignKeys) | **GET** /rest/v2/contact/byHcPartySecretForeignKeys/delegations | List contacts found By Healthcare Party and secret foreign keys.
[**listServicesByAssociationId**](ContactApi.md#listServicesByAssociationId) | **GET** /rest/v2/contact/service/associationId | List services by related association id
[**matchContactsBy**](ContactApi.md#matchContactsBy) | **POST** /rest/v2/contact/match | Get ids of contacts matching the provided filter for the current user (HcParty) 
[**modifyContact**](ContactApi.md#modifyContact) | **PUT** /rest/v2/contact | Modify a contact
[**modifyContacts**](ContactApi.md#modifyContacts) | **PUT** /rest/v2/contact/batch | Modify a batch of contacts
[**modifyContactsDelegations**](ContactApi.md#modifyContactsDelegations) | **PUT** /rest/v2/contact/delegations | Update delegations in healthElements.
[**newContactDelegations**](ContactApi.md#newContactDelegations) | **POST** /rest/v2/contact/{contactId}/delegate | Delegates a contact to a healthcare party
[**setContactsDelegations**](ContactApi.md#setContactsDelegations) | **POST** /rest/v2/contact/delegations | Update delegations in healthElements.


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

Returns an instance of created contact.

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
> kotlin.collections.List&lt;DocIdentifier&gt; deleteContacts(listOfIdsDto)

Delete contacts.

Response is a set containing the ID&#39;s of deleted contacts.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteContacts(listOfIdsDto)
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
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
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

<a name="findContactsByOpeningDate"></a>
# **findContactsByOpeningDate**
> PaginatedListContactDto findContactsByOpeningDate(startKey, endKey, hcpartyid, startDocumentId, limit)

List contacts by opening date parties with(out) pagination

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
    val result : PaginatedListContactDto = apiInstance.findContactsByOpeningDate(startKey, endKey, hcpartyid, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#findContactsByOpeningDate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#findContactsByOpeningDate")
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

<a name="getContact"></a>
# **getContact**
> ContactDto getContact(contactId)

Get a contact

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

Get contacts

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

<a name="getServiceByHealthcarepartyAndIdentifier"></a>
# **getServiceByHealthcarepartyAndIdentifier**
> ServiceDto getServiceByHealthcarepartyAndIdentifier(hcPartyId, `value`, system)

Get service by identifier

It gets service data based on the identifier (root &amp; extension) parameters.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val `value` : kotlin.String = `value`_example // kotlin.String | 
val system : kotlin.String = system_example // kotlin.String | 
try {
    val result : ServiceDto = apiInstance.getServiceByHealthcarepartyAndIdentifier(hcPartyId, `value`, system)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#getServiceByHealthcarepartyAndIdentifier")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#getServiceByHealthcarepartyAndIdentifier")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **&#x60;value&#x60;** | **kotlin.String**|  |
 **system** | **kotlin.String**|  | [optional]

### Return type

[**ServiceDto**](ServiceDto.md)

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

<a name="getServices"></a>
# **getServices**
> kotlin.collections.List&lt;ServiceDto&gt; getServices(listOfIdsDto)

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
    val result : kotlin.collections.List<ServiceDto> = apiInstance.getServices(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#getServices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#getServices")
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

<a name="getServicesIdsByHealthcarePartyAndIdentifiers"></a>
# **getServicesIdsByHealthcarePartyAndIdentifiers**
> kotlin.collections.List&lt;IndexedIdentifierDto&gt; getServicesIdsByHealthcarePartyAndIdentifiers(hcPartyId, identifiers)

Get services ids by identifiers

For each provided identifier, links corresponding iCure service id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val identifiers : kotlin.collections.List<IdentifierDto> =  // kotlin.collections.List<IdentifierDto> | 
try {
    val result : kotlin.collections.List<IndexedIdentifierDto> = apiInstance.getServicesIdsByHealthcarePartyAndIdentifiers(hcPartyId, identifiers)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#getServicesIdsByHealthcarePartyAndIdentifiers")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#getServicesIdsByHealthcarePartyAndIdentifiers")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **identifiers** | [**kotlin.collections.List&lt;IdentifierDto&gt;**](IdentifierDto.md)|  | [default to emptyList()]

### Return type

[**kotlin.collections.List&lt;IndexedIdentifierDto&gt;**](IndexedIdentifierDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getServicesLinkedTo"></a>
# **getServicesLinkedTo**
> kotlin.collections.List&lt;ServiceDto&gt; getServicesLinkedTo(listOfIdsDto, linkType)

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
    val result : kotlin.collections.List<ServiceDto> = apiInstance.getServicesLinkedTo(listOfIdsDto, linkType)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#getServicesLinkedTo")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#getServicesLinkedTo")
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

<a name="listContactByHCPartyServiceId"></a>
# **listContactByHCPartyServiceId**
> kotlin.collections.List&lt;ContactDto&gt; listContactByHCPartyServiceId(hcPartyId, serviceId)

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
    val result : kotlin.collections.List<ContactDto> = apiInstance.listContactByHCPartyServiceId(hcPartyId, serviceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listContactByHCPartyServiceId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listContactByHCPartyServiceId")
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

<a name="listContactsByExternalId"></a>
# **listContactsByExternalId**
> kotlin.collections.List&lt;ContactDto&gt; listContactsByExternalId(externalId)

List contacts found By externalId.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val externalId : kotlin.String = externalId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.listContactsByExternalId(externalId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listContactsByExternalId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listContactsByExternalId")
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

<a name="listContactsByHCPartyAndFormId"></a>
# **listContactsByHCPartyAndFormId**
> kotlin.collections.List&lt;ContactDto&gt; listContactsByHCPartyAndFormId(hcPartyId, formId)

List contacts found By Healthcare Party and form Id.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val formId : kotlin.String = formId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.listContactsByHCPartyAndFormId(hcPartyId, formId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listContactsByHCPartyAndFormId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listContactsByHCPartyAndFormId")
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

<a name="listContactsByHCPartyAndFormIds"></a>
# **listContactsByHCPartyAndFormIds**
> kotlin.collections.List&lt;ContactDto&gt; listContactsByHCPartyAndFormIds(hcPartyId, listOfIdsDto)

List contacts found By Healthcare Party and form Id.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.listContactsByHCPartyAndFormIds(hcPartyId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listContactsByHCPartyAndFormIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listContactsByHCPartyAndFormIds")
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

<a name="listContactsByHCPartyAndPatientForeignKeys"></a>
# **listContactsByHCPartyAndPatientForeignKeys**
> kotlin.collections.List&lt;ContactDto&gt; listContactsByHCPartyAndPatientForeignKeys(hcPartyId, listOfIdsDto)

List contacts found By Healthcare Party and Patient foreign keys.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ContactApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.listContactsByHCPartyAndPatientForeignKeys(hcPartyId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listContactsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listContactsByHCPartyAndPatientForeignKeys")
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

<a name="listContactsByHCPartyAndPatientSecretFKeys"></a>
# **listContactsByHCPartyAndPatientSecretFKeys**
> kotlin.collections.List&lt;ContactDto&gt; listContactsByHCPartyAndPatientSecretFKeys(hcPartyId, secretFKeys, planOfActionsIds, skipClosedContacts)

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
val planOfActionsIds : kotlin.String = planOfActionsIds_example // kotlin.String | 
val skipClosedContacts : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.listContactsByHCPartyAndPatientSecretFKeys(hcPartyId, secretFKeys, planOfActionsIds, skipClosedContacts)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listContactsByHCPartyAndPatientSecretFKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listContactsByHCPartyAndPatientSecretFKeys")
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

<a name="listContactsDelegationsStubsByHCPartyAndPatientForeignKeys"></a>
# **listContactsDelegationsStubsByHCPartyAndPatientForeignKeys**
> kotlin.collections.List&lt;IcureStubDto&gt; listContactsDelegationsStubsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)

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
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.listContactsDelegationsStubsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#listContactsDelegationsStubsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#listContactsDelegationsStubsByHCPartyAndPatientForeignKeys")
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

<a name="modifyContactsDelegations"></a>
# **modifyContactsDelegations**
> kotlin.collections.List&lt;ContactDto&gt; modifyContactsDelegations(icureStubDto)

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
    val result : kotlin.collections.List<ContactDto> = apiInstance.modifyContactsDelegations(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ContactApi#modifyContactsDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ContactApi#modifyContactsDelegations")
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

