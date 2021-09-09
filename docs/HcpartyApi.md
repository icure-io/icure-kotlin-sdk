# HcpartyApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createHealthcareParty**](HcpartyApi.md#createHealthcareParty) | **POST** /rest/v1/hcparty | Create a healthcare party
[**createHealthcarePartyInGroup**](HcpartyApi.md#createHealthcarePartyInGroup) | **POST** /rest/v1/hcparty/inGroup/{groupId} | Create a healthcare party
[**deleteHealthcareParties**](HcpartyApi.md#deleteHealthcareParties) | **DELETE** /rest/v1/hcparty/{healthcarePartyIds} | Delete a healthcare party
[**deleteHealthcarePartiesInGroup**](HcpartyApi.md#deleteHealthcarePartiesInGroup) | **DELETE** /rest/v1/hcparty/inGroup/{groupId}/{healthcarePartyIds} | Delete a healthcare party
[**findByName**](HcpartyApi.md#findByName) | **GET** /rest/v1/hcparty/byName | Find healthcare parties by name with(out) pagination
[**findBySpecialityAndPostCode**](HcpartyApi.md#findBySpecialityAndPostCode) | **GET** /rest/v1/hcparty/bySpecialityAndPostCode/{type}/{spec}/{firstCode}/to/{lastCode} | Find healthcare parties by name with(out) pagination
[**findBySsinOrNihii**](HcpartyApi.md#findBySsinOrNihii) | **GET** /rest/v1/hcparty/byNihiiOrSsin/{searchValue} | Find healthcare parties by nihii or ssin with(out) pagination
[**getCurrentHealthcareParty**](HcpartyApi.md#getCurrentHealthcareParty) | **GET** /rest/v1/hcparty/current | Get the current healthcare party if logged in.
[**getHcPartyKeysForDelegate**](HcpartyApi.md#getHcPartyKeysForDelegate) | **GET** /rest/v1/hcparty/{healthcarePartyId}/keys | Get the HcParty encrypted AES keys indexed by owner
[**getHealthcareParties**](HcpartyApi.md#getHealthcareParties) | **GET** /rest/v1/hcparty/byIds/{healthcarePartyIds} | Get healthcareParties by their IDs
[**getHealthcarePartiesByParentId**](HcpartyApi.md#getHealthcarePartiesByParentId) | **GET** /rest/v1/hcparty/{parentId}/children | Find children of an healthcare parties
[**getHealthcarePartiesInGroup**](HcpartyApi.md#getHealthcarePartiesInGroup) | **POST** /rest/v1/hcparty/inGroup/{groupId}/byIds | Get healthcareParties by their IDs
[**getHealthcareParty**](HcpartyApi.md#getHealthcareParty) | **GET** /rest/v1/hcparty/{healthcarePartyId} | Get a healthcareParty by his ID
[**getPublicKey**](HcpartyApi.md#getPublicKey) | **GET** /rest/v1/hcparty/{healthcarePartyId}/publicKey | Get public key of a healthcare party
[**listByName**](HcpartyApi.md#listByName) | **GET** /rest/v1/hcparty/byNameStrict/{name} | Find healthcare parties by name with(out) pagination
[**listHealthcareParties**](HcpartyApi.md#listHealthcareParties) | **GET** /rest/v1/hcparty | List healthcare parties with(out) pagination
[**modifyHealthcareParty**](HcpartyApi.md#modifyHealthcareParty) | **PUT** /rest/v1/hcparty | Modify a Healthcare Party.
[**modifyHealthcarePartyInGroup**](HcpartyApi.md#modifyHealthcarePartyInGroup) | **PUT** /rest/v1/hcparty/inGroup/{groupId} | Modify a Healthcare Party.


<a name="createHealthcareParty"></a>
# **createHealthcareParty**
> HealthcarePartyDto createHealthcareParty(healthcarePartyDto)

Create a healthcare party

One of Name or Last name+First name, Nihii, and Public key are required.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val healthcarePartyDto : HealthcarePartyDto =  // HealthcarePartyDto | 
try {
    val result : HealthcarePartyDto = apiInstance.createHealthcareParty(healthcarePartyDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#createHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#createHealthcareParty")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthcarePartyDto** | [**HealthcarePartyDto**](HealthcarePartyDto.md)|  |

### Return type

[**HealthcarePartyDto**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createHealthcarePartyInGroup"></a>
# **createHealthcarePartyInGroup**
> HealthcarePartyDto createHealthcarePartyInGroup(groupId, healthcarePartyDto)

Create a healthcare party

One of Name or Last name+First name, Nihii, and Public key are required.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val healthcarePartyDto : HealthcarePartyDto =  // HealthcarePartyDto | 
try {
    val result : HealthcarePartyDto = apiInstance.createHealthcarePartyInGroup(groupId, healthcarePartyDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#createHealthcarePartyInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#createHealthcarePartyInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **healthcarePartyDto** | [**HealthcarePartyDto**](HealthcarePartyDto.md)|  |

### Return type

[**HealthcarePartyDto**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteHealthcareParties"></a>
# **deleteHealthcareParties**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteHealthcareParties(healthcarePartyIds)

Delete a healthcare party

Deleting a healthcareParty. Response is an array containing the id of deleted healthcare party.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val healthcarePartyIds : kotlin.String = healthcarePartyIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteHealthcareParties(healthcarePartyIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#deleteHealthcareParties")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#deleteHealthcareParties")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthcarePartyIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deleteHealthcarePartiesInGroup"></a>
# **deleteHealthcarePartiesInGroup**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteHealthcarePartiesInGroup(groupId, healthcarePartyIds)

Delete a healthcare party

Deleting a healthcareParty. Response is an array containing the id of deleted healthcare party.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val healthcarePartyIds : kotlin.String = healthcarePartyIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteHealthcarePartiesInGroup(groupId, healthcarePartyIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#deleteHealthcarePartiesInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#deleteHealthcarePartiesInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **healthcarePartyIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findByName"></a>
# **findByName**
> PaginatedListHealthcarePartyDto findByName(name, startKey, startDocumentId, limit, desc)

Find healthcare parties by name with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val name : kotlin.String = name_example // kotlin.String | The Last name search value
val startKey : kotlin.String = startKey_example // kotlin.String | A healthcare party Last name
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A healthcare party document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val desc : kotlin.Boolean = true // kotlin.Boolean | Descending
try {
    val result : PaginatedListHealthcarePartyDto = apiInstance.findByName(name, startKey, startDocumentId, limit, desc)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#findByName")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#findByName")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **kotlin.String**| The Last name search value | [optional]
 **startKey** | **kotlin.String**| A healthcare party Last name | [optional]
 **startDocumentId** | **kotlin.String**| A healthcare party document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]
 **desc** | **kotlin.Boolean**| Descending | [optional]

### Return type

[**PaginatedListHealthcarePartyDto**](PaginatedListHealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findBySpecialityAndPostCode"></a>
# **findBySpecialityAndPostCode**
> PaginatedListHealthcarePartyDto findBySpecialityAndPostCode(type, spec, firstCode, lastCode, limit)

Find healthcare parties by name with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val type : kotlin.String = type_example // kotlin.String | The type of the HCP (persphysician)
val spec : kotlin.String = spec_example // kotlin.String | The speciality of the HCP
val firstCode : kotlin.String = firstCode_example // kotlin.String | The first postCode for the HCP
val lastCode : kotlin.String = lastCode_example // kotlin.String | The last postCode for the HCP
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListHealthcarePartyDto = apiInstance.findBySpecialityAndPostCode(type, spec, firstCode, lastCode, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#findBySpecialityAndPostCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#findBySpecialityAndPostCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **type** | **kotlin.String**| The type of the HCP (persphysician) |
 **spec** | **kotlin.String**| The speciality of the HCP |
 **firstCode** | **kotlin.String**| The first postCode for the HCP |
 **lastCode** | **kotlin.String**| The last postCode for the HCP |
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListHealthcarePartyDto**](PaginatedListHealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findBySsinOrNihii"></a>
# **findBySsinOrNihii**
> PaginatedListHealthcarePartyDto findBySsinOrNihii(searchValue, startKey, startDocumentId, limit, desc)

Find healthcare parties by nihii or ssin with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val searchValue : kotlin.String = searchValue_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | A healthcare party Last name
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A healthcare party document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val desc : kotlin.Boolean = true // kotlin.Boolean | Descending
try {
    val result : PaginatedListHealthcarePartyDto = apiInstance.findBySsinOrNihii(searchValue, startKey, startDocumentId, limit, desc)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#findBySsinOrNihii")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#findBySsinOrNihii")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **searchValue** | **kotlin.String**|  |
 **startKey** | **kotlin.String**| A healthcare party Last name | [optional]
 **startDocumentId** | **kotlin.String**| A healthcare party document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]
 **desc** | **kotlin.Boolean**| Descending | [optional]

### Return type

[**PaginatedListHealthcarePartyDto**](PaginatedListHealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCurrentHealthcareParty"></a>
# **getCurrentHealthcareParty**
> HealthcarePartyDto getCurrentHealthcareParty()

Get the current healthcare party if logged in.

General information about the current healthcare Party

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
try {
    val result : HealthcarePartyDto = apiInstance.getCurrentHealthcareParty()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#getCurrentHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#getCurrentHealthcareParty")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**HealthcarePartyDto**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getHcPartyKeysForDelegate"></a>
# **getHcPartyKeysForDelegate**
> kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt; getHcPartyKeysForDelegate(healthcarePartyId)

Get the HcParty encrypted AES keys indexed by owner

(key, value) of the map is as follows: (ID of the owner of the encrypted AES key, encrypted AES key)

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val healthcarePartyId : kotlin.String = healthcarePartyId_example // kotlin.String | 
try {
    val result : kotlin.collections.Map<kotlin.String, kotlin.String> = apiInstance.getHcPartyKeysForDelegate(healthcarePartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#getHcPartyKeysForDelegate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#getHcPartyKeysForDelegate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthcarePartyId** | **kotlin.String**|  |

### Return type

**kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getHealthcareParties"></a>
# **getHealthcareParties**
> kotlin.collections.List&lt;HealthcarePartyDto&gt; getHealthcareParties(healthcarePartyIds)

Get healthcareParties by their IDs

General information about the healthcare Party

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val healthcarePartyIds : kotlin.String = healthcarePartyIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<HealthcarePartyDto> = apiInstance.getHealthcareParties(healthcarePartyIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#getHealthcareParties")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#getHealthcareParties")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthcarePartyIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;HealthcarePartyDto&gt;**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getHealthcarePartiesByParentId"></a>
# **getHealthcarePartiesByParentId**
> kotlin.collections.List&lt;HealthcarePartyDto&gt; getHealthcarePartiesByParentId(parentId)

Find children of an healthcare parties

Return a list of children hcp.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val parentId : kotlin.String = parentId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<HealthcarePartyDto> = apiInstance.getHealthcarePartiesByParentId(parentId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#getHealthcarePartiesByParentId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#getHealthcarePartiesByParentId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **parentId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;HealthcarePartyDto&gt;**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getHealthcarePartiesInGroup"></a>
# **getHealthcarePartiesInGroup**
> kotlin.collections.List&lt;HealthcarePartyDto&gt; getHealthcarePartiesInGroup(groupId, listOfIdsDto)

Get healthcareParties by their IDs

General information about the healthcare Party

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<HealthcarePartyDto> = apiInstance.getHealthcarePartiesInGroup(groupId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#getHealthcarePartiesInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#getHealthcarePartiesInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;HealthcarePartyDto&gt;**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getHealthcareParty"></a>
# **getHealthcareParty**
> HealthcarePartyDto getHealthcareParty(healthcarePartyId)

Get a healthcareParty by his ID

General information about the healthcare Party

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val healthcarePartyId : kotlin.String = healthcarePartyId_example // kotlin.String | 
try {
    val result : HealthcarePartyDto = apiInstance.getHealthcareParty(healthcarePartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#getHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#getHealthcareParty")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthcarePartyId** | **kotlin.String**|  |

### Return type

[**HealthcarePartyDto**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getPublicKey"></a>
# **getPublicKey**
> PublicKeyDto getPublicKey(healthcarePartyId)

Get public key of a healthcare party

Returns the public key of a healthcare party in Hex

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val healthcarePartyId : kotlin.String = healthcarePartyId_example // kotlin.String | 
try {
    val result : PublicKeyDto = apiInstance.getPublicKey(healthcarePartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#getPublicKey")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#getPublicKey")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthcarePartyId** | **kotlin.String**|  |

### Return type

[**PublicKeyDto**](PublicKeyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listByName"></a>
# **listByName**
> kotlin.collections.List&lt;HealthcarePartyDto&gt; listByName(name)

Find healthcare parties by name with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val name : kotlin.String = name_example // kotlin.String | The Last name search value
try {
    val result : kotlin.collections.List<HealthcarePartyDto> = apiInstance.listByName(name)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#listByName")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#listByName")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **kotlin.String**| The Last name search value |

### Return type

[**kotlin.collections.List&lt;HealthcarePartyDto&gt;**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listHealthcareParties"></a>
# **listHealthcareParties**
> PaginatedListHealthcarePartyDto listHealthcareParties(startKey, startDocumentId, limit, desc)

List healthcare parties with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val startKey : kotlin.String = startKey_example // kotlin.String | A healthcare party Last name
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A healthcare party document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val desc : kotlin.Boolean = true // kotlin.Boolean | Descending
try {
    val result : PaginatedListHealthcarePartyDto = apiInstance.listHealthcareParties(startKey, startDocumentId, limit, desc)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#listHealthcareParties")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#listHealthcareParties")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startKey** | **kotlin.String**| A healthcare party Last name | [optional]
 **startDocumentId** | **kotlin.String**| A healthcare party document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]
 **desc** | **kotlin.Boolean**| Descending | [optional]

### Return type

[**PaginatedListHealthcarePartyDto**](PaginatedListHealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyHealthcareParty"></a>
# **modifyHealthcareParty**
> HealthcarePartyDto modifyHealthcareParty(healthcarePartyDto)

Modify a Healthcare Party.

No particular return value. It&#39;s just a message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val healthcarePartyDto : HealthcarePartyDto =  // HealthcarePartyDto | 
try {
    val result : HealthcarePartyDto = apiInstance.modifyHealthcareParty(healthcarePartyDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#modifyHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#modifyHealthcareParty")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthcarePartyDto** | [**HealthcarePartyDto**](HealthcarePartyDto.md)|  |

### Return type

[**HealthcarePartyDto**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyHealthcarePartyInGroup"></a>
# **modifyHealthcarePartyInGroup**
> HealthcarePartyDto modifyHealthcarePartyInGroup(groupId, healthcarePartyDto)

Modify a Healthcare Party.

No particular return value. It&#39;s just a message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HcpartyApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val healthcarePartyDto : HealthcarePartyDto =  // HealthcarePartyDto | 
try {
    val result : HealthcarePartyDto = apiInstance.modifyHealthcarePartyInGroup(groupId, healthcarePartyDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HcpartyApi#modifyHealthcarePartyInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HcpartyApi#modifyHealthcarePartyInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **healthcarePartyDto** | [**HealthcarePartyDto**](HealthcarePartyDto.md)|  |

### Return type

[**HealthcarePartyDto**](HealthcarePartyDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

