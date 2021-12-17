# HealthcarePartyApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createHealthcareParty**](HealthcarePartyApi.md#createHealthcareParty) | **POST** /rest/v2/hcparty | Create a healthcare party
[**createHealthcarePartyInGroup**](HealthcarePartyApi.md#createHealthcarePartyInGroup) | **POST** /rest/v2/hcparty/inGroup/{groupId} | Create a healthcare party
[**deleteHealthcareParties**](HealthcarePartyApi.md#deleteHealthcareParties) | **POST** /rest/v2/hcparty/delete/batch | Delete healthcare parties
[**deleteHealthcarePartiesInGroup**](HealthcarePartyApi.md#deleteHealthcarePartiesInGroup) | **POST** /rest/v2/hcparty/delete/batch/inGroup/{groupId} | Delete a healthcare party
[**findHealthcarePartiesBy**](HealthcarePartyApi.md#findHealthcarePartiesBy) | **GET** /rest/v2/hcparty | List healthcare parties with(out) pagination
[**findHealthcarePartiesByName**](HealthcarePartyApi.md#findHealthcarePartiesByName) | **GET** /rest/v2/hcparty/byName | Find healthcare parties by name with(out) pagination
[**findHealthcarePartiesBySpecialityAndPostCode**](HealthcarePartyApi.md#findHealthcarePartiesBySpecialityAndPostCode) | **GET** /rest/v2/hcparty/bySpecialityAndPostCode/{type}/{spec}/{firstCode}/to/{lastCode} | Find healthcare parties by name with(out) pagination
[**findHealthcarePartiesBySsinOrNihii**](HealthcarePartyApi.md#findHealthcarePartiesBySsinOrNihii) | **GET** /rest/v2/hcparty/byNihiiOrSsin/{searchValue} | Find healthcare parties by nihii or ssin with(out) pagination
[**getCurrentHealthcareParty**](HealthcarePartyApi.md#getCurrentHealthcareParty) | **GET** /rest/v2/hcparty/current | Get the current healthcare party if logged in.
[**getHcPartyKeysForDelegate**](HealthcarePartyApi.md#getHcPartyKeysForDelegate) | **GET** /rest/v2/hcparty/byKeys/{healthcarePartyId} | Get the HcParty encrypted AES keys indexed by owner
[**getHealthcareParties**](HealthcarePartyApi.md#getHealthcareParties) | **POST** /rest/v2/hcparty/byIds | Get healthcareParties by their IDs
[**getHealthcareParty**](HealthcarePartyApi.md#getHealthcareParty) | **GET** /rest/v2/hcparty/{healthcarePartyId} | Get a healthcareParty by his ID
[**getPublicKey**](HealthcarePartyApi.md#getPublicKey) | **GET** /rest/v2/hcparty/{healthcarePartyId}/publicKey | Get public key of a healthcare party
[**listHealthcarePartiesByName**](HealthcarePartyApi.md#listHealthcarePartiesByName) | **GET** /rest/v2/hcparty/byNameStrict/{name} | Find healthcare parties by name with(out) pagination
[**listHealthcarePartiesByParentId**](HealthcarePartyApi.md#listHealthcarePartiesByParentId) | **GET** /rest/v2/hcparty/{parentId}/children | Find children of an healthcare parties
[**modifyHealthcareParty**](HealthcarePartyApi.md#modifyHealthcareParty) | **PUT** /rest/v2/hcparty | Modify a Healthcare Party.
[**modifyHealthcarePartyInGroup**](HealthcarePartyApi.md#modifyHealthcarePartyInGroup) | **PUT** /rest/v2/hcparty/inGroup/{groupId} | Modify a Healthcare Party.


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

val apiInstance = HealthcarePartyApi()
val healthcarePartyDto : HealthcarePartyDto =  // HealthcarePartyDto | 
try {
    val result : HealthcarePartyDto = apiInstance.createHealthcareParty(healthcarePartyDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#createHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#createHealthcareParty")
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

val apiInstance = HealthcarePartyApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val healthcarePartyDto : HealthcarePartyDto =  // HealthcarePartyDto | 
try {
    val result : HealthcarePartyDto = apiInstance.createHealthcarePartyInGroup(groupId, healthcarePartyDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#createHealthcarePartyInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#createHealthcarePartyInGroup")
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
> kotlin.collections.List&lt;DocIdentifier&gt; deleteHealthcareParties(listOfIdsDto)

Delete healthcare parties

Deleting healthcareParties. Response is an array containing the id of deleted healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HealthcarePartyApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteHealthcareParties(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#deleteHealthcareParties")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#deleteHealthcareParties")
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

<a name="deleteHealthcarePartiesInGroup"></a>
# **deleteHealthcarePartiesInGroup**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteHealthcarePartiesInGroup(groupId, listOfIdsDto)

Delete a healthcare party

Deleting a healthcareParty. Response is an array containing the id of deleted healthcare party.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HealthcarePartyApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteHealthcarePartiesInGroup(groupId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#deleteHealthcarePartiesInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#deleteHealthcarePartiesInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findHealthcarePartiesBy"></a>
# **findHealthcarePartiesBy**
> PaginatedListHealthcarePartyDto findHealthcarePartiesBy(startKey, startDocumentId, limit, desc)

List healthcare parties with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HealthcarePartyApi()
val startKey : kotlin.String = startKey_example // kotlin.String | A healthcare party Last name
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A healthcare party document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val desc : kotlin.Boolean = true // kotlin.Boolean | Descending
try {
    val result : PaginatedListHealthcarePartyDto = apiInstance.findHealthcarePartiesBy(startKey, startDocumentId, limit, desc)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#findHealthcarePartiesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#findHealthcarePartiesBy")
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

<a name="findHealthcarePartiesByName"></a>
# **findHealthcarePartiesByName**
> PaginatedListHealthcarePartyDto findHealthcarePartiesByName(name, startKey, startDocumentId, limit, desc)

Find healthcare parties by name with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HealthcarePartyApi()
val name : kotlin.String = name_example // kotlin.String | The Last name search value
val startKey : kotlin.String = startKey_example // kotlin.String | A healthcare party Last name
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A healthcare party document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val desc : kotlin.Boolean = true // kotlin.Boolean | Descending
try {
    val result : PaginatedListHealthcarePartyDto = apiInstance.findHealthcarePartiesByName(name, startKey, startDocumentId, limit, desc)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#findHealthcarePartiesByName")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#findHealthcarePartiesByName")
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

<a name="findHealthcarePartiesBySpecialityAndPostCode"></a>
# **findHealthcarePartiesBySpecialityAndPostCode**
> PaginatedListHealthcarePartyDto findHealthcarePartiesBySpecialityAndPostCode(type, spec, firstCode, lastCode, limit)

Find healthcare parties by name with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HealthcarePartyApi()
val type : kotlin.String = type_example // kotlin.String | The type of the HCP (persphysician)
val spec : kotlin.String = spec_example // kotlin.String | The speciality of the HCP
val firstCode : kotlin.String = firstCode_example // kotlin.String | The first postCode for the HCP
val lastCode : kotlin.String = lastCode_example // kotlin.String | The last postCode for the HCP
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListHealthcarePartyDto = apiInstance.findHealthcarePartiesBySpecialityAndPostCode(type, spec, firstCode, lastCode, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#findHealthcarePartiesBySpecialityAndPostCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#findHealthcarePartiesBySpecialityAndPostCode")
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

<a name="findHealthcarePartiesBySsinOrNihii"></a>
# **findHealthcarePartiesBySsinOrNihii**
> PaginatedListHealthcarePartyDto findHealthcarePartiesBySsinOrNihii(searchValue, startKey, startDocumentId, limit, desc)

Find healthcare parties by nihii or ssin with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HealthcarePartyApi()
val searchValue : kotlin.String = searchValue_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | A healthcare party Last name
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A healthcare party document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val desc : kotlin.Boolean = true // kotlin.Boolean | Descending
try {
    val result : PaginatedListHealthcarePartyDto = apiInstance.findHealthcarePartiesBySsinOrNihii(searchValue, startKey, startDocumentId, limit, desc)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#findHealthcarePartiesBySsinOrNihii")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#findHealthcarePartiesBySsinOrNihii")
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

val apiInstance = HealthcarePartyApi()
try {
    val result : HealthcarePartyDto = apiInstance.getCurrentHealthcareParty()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#getCurrentHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#getCurrentHealthcareParty")
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

val apiInstance = HealthcarePartyApi()
val healthcarePartyId : kotlin.String = healthcarePartyId_example // kotlin.String | 
try {
    val result : kotlin.collections.Map<kotlin.String, kotlin.String> = apiInstance.getHcPartyKeysForDelegate(healthcarePartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#getHcPartyKeysForDelegate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#getHcPartyKeysForDelegate")
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
> kotlin.collections.List&lt;HealthcarePartyDto&gt; getHealthcareParties(listOfIdsDto)

Get healthcareParties by their IDs

General information about the healthcare Party

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HealthcarePartyApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<HealthcarePartyDto> = apiInstance.getHealthcareParties(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#getHealthcareParties")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#getHealthcareParties")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

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

val apiInstance = HealthcarePartyApi()
val healthcarePartyId : kotlin.String = healthcarePartyId_example // kotlin.String | 
try {
    val result : HealthcarePartyDto = apiInstance.getHealthcareParty(healthcarePartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#getHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#getHealthcareParty")
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

val apiInstance = HealthcarePartyApi()
val healthcarePartyId : kotlin.String = healthcarePartyId_example // kotlin.String | 
try {
    val result : PublicKeyDto = apiInstance.getPublicKey(healthcarePartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#getPublicKey")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#getPublicKey")
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

<a name="listHealthcarePartiesByName"></a>
# **listHealthcarePartiesByName**
> kotlin.collections.List&lt;HealthcarePartyDto&gt; listHealthcarePartiesByName(name)

Find healthcare parties by name with(out) pagination

Returns a list of healthcare parties.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HealthcarePartyApi()
val name : kotlin.String = name_example // kotlin.String | The Last name search value
try {
    val result : kotlin.collections.List<HealthcarePartyDto> = apiInstance.listHealthcarePartiesByName(name)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#listHealthcarePartiesByName")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#listHealthcarePartiesByName")
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

<a name="listHealthcarePartiesByParentId"></a>
# **listHealthcarePartiesByParentId**
> kotlin.collections.List&lt;HealthcarePartyDto&gt; listHealthcarePartiesByParentId(parentId)

Find children of an healthcare parties

Return a list of children hcp.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HealthcarePartyApi()
val parentId : kotlin.String = parentId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<HealthcarePartyDto> = apiInstance.listHealthcarePartiesByParentId(parentId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#listHealthcarePartiesByParentId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#listHealthcarePartiesByParentId")
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

val apiInstance = HealthcarePartyApi()
val healthcarePartyDto : HealthcarePartyDto =  // HealthcarePartyDto | 
try {
    val result : HealthcarePartyDto = apiInstance.modifyHealthcareParty(healthcarePartyDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#modifyHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#modifyHealthcareParty")
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

val apiInstance = HealthcarePartyApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val healthcarePartyDto : HealthcarePartyDto =  // HealthcarePartyDto | 
try {
    val result : HealthcarePartyDto = apiInstance.modifyHealthcarePartyInGroup(groupId, healthcarePartyDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HealthcarePartyApi#modifyHealthcarePartyInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HealthcarePartyApi#modifyHealthcarePartyInGroup")
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

