# HelementApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createHealthElement**](HelementApi.md#createHealthElement) | **POST** /rest/v2/helement | Create a health element with the current user
[**createHealthElements**](HelementApi.md#createHealthElements) | **POST** /rest/v2/helement/batch | Create a batch of healthcare elements
[**deleteHealthElements**](HelementApi.md#deleteHealthElements) | **DELETE** /rest/v2/helement/delete/batch | Delete health elements.
[**filterHealthElementsBy**](HelementApi.md#filterHealthElementsBy) | **POST** /rest/v2/helement/filter | Filter health elements for the current user (HcParty)
[**getHealthElement**](HelementApi.md#getHealthElement) | **GET** /rest/v2/helement/{healthElementId} | Get a health element
[**listHealthElementsByHCPartyAndPatientForeignKeys**](HelementApi.md#listHealthElementsByHCPartyAndPatientForeignKeys) | **GET** /rest/v2/helement/byHcPartySecretForeignKeys | List health elements found By Healthcare Party and secret foreign keyelementIds.
[**listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys**](HelementApi.md#listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys) | **GET** /rest/v2/helement/byHcPartySecretForeignKeys/delegations | List helement stubs found By Healthcare Party and secret foreign keys.
[**modifyHealthElement**](HelementApi.md#modifyHealthElement) | **PUT** /rest/v2/helement | Modify a health element
[**modifyHealthElements**](HelementApi.md#modifyHealthElements) | **PUT** /rest/v2/helement/batch | Modify a batch of health elements
[**newHealthElementDelegations**](HelementApi.md#newHealthElementDelegations) | **POST** /rest/v2/helement/{healthElementId}/delegate | Delegates a health element to a healthcare party
[**setHealthElementsDelegations**](HelementApi.md#setHealthElementsDelegations) | **POST** /rest/v2/helement/delegations | Update delegations in healthElements.


<a name="createHealthElement"></a>
# **createHealthElement**
> HealthElementDto createHealthElement(healthElementDto)

Create a health element with the current user

Returns an instance of created health element.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val healthElementDto : HealthElementDto =  // HealthElementDto | 
try {
    val result : HealthElementDto = apiInstance.createHealthElement(healthElementDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#createHealthElement")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#createHealthElement")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthElementDto** | [**HealthElementDto**](HealthElementDto.md)|  |

### Return type

[**HealthElementDto**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createHealthElements"></a>
# **createHealthElements**
> kotlin.collections.List&lt;HealthElementDto&gt; createHealthElements(healthElementDto)

Create a batch of healthcare elements

Returns the created healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val healthElementDto : kotlin.collections.List<HealthElementDto> =  // kotlin.collections.List<HealthElementDto> | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.createHealthElements(healthElementDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#createHealthElements")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#createHealthElements")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthElementDto** | [**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)|  |

### Return type

[**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteHealthElements"></a>
# **deleteHealthElements**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteHealthElements(listOfIdsDto)

Delete health elements.

Response is a set containing the ID&#39;s of deleted health elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteHealthElements(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#deleteHealthElements")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#deleteHealthElements")
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

<a name="filterHealthElementsBy"></a>
# **filterHealthElementsBy**
> kotlin.collections.List&lt;HealthElementDto&gt; filterHealthElementsBy(filterChainHealthElement)

Filter health elements for the current user (HcParty)

Returns a list of health elements along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val filterChainHealthElement : FilterChainHealthElement =  // FilterChainHealthElement | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.filterHealthElementsBy(filterChainHealthElement)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#filterHealthElementsBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#filterHealthElementsBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterChainHealthElement** | [**FilterChainHealthElement**](FilterChainHealthElement.md)|  |

### Return type

[**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getHealthElement"></a>
# **getHealthElement**
> HealthElementDto getHealthElement(healthElementId)

Get a health element

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val healthElementId : kotlin.String = healthElementId_example // kotlin.String | 
try {
    val result : HealthElementDto = apiInstance.getHealthElement(healthElementId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#getHealthElement")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#getHealthElement")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthElementId** | **kotlin.String**|  |

### Return type

[**HealthElementDto**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listHealthElementsByHCPartyAndPatientForeignKeys"></a>
# **listHealthElementsByHCPartyAndPatientForeignKeys**
> kotlin.collections.List&lt;HealthElementDto&gt; listHealthElementsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)

List health elements found By Healthcare Party and secret foreign keyelementIds.

Keys hast to delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.listHealthElementsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#listHealthElementsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#listHealthElementsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys"></a>
# **listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys**
> kotlin.collections.List&lt;IcureStubDto&gt; listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)

List helement stubs found By Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys")
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

<a name="modifyHealthElement"></a>
# **modifyHealthElement**
> HealthElementDto modifyHealthElement(healthElementDto)

Modify a health element

Returns the modified health element.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val healthElementDto : HealthElementDto =  // HealthElementDto | 
try {
    val result : HealthElementDto = apiInstance.modifyHealthElement(healthElementDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#modifyHealthElement")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#modifyHealthElement")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthElementDto** | [**HealthElementDto**](HealthElementDto.md)|  |

### Return type

[**HealthElementDto**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyHealthElements"></a>
# **modifyHealthElements**
> kotlin.collections.List&lt;HealthElementDto&gt; modifyHealthElements(healthElementDto)

Modify a batch of health elements

Returns the modified health elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val healthElementDto : kotlin.collections.List<HealthElementDto> =  // kotlin.collections.List<HealthElementDto> | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.modifyHealthElements(healthElementDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#modifyHealthElements")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#modifyHealthElements")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthElementDto** | [**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)|  |

### Return type

[**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="newHealthElementDelegations"></a>
# **newHealthElementDelegations**
> HealthElementDto newHealthElementDelegations(healthElementId, delegationDto)

Delegates a health element to a healthcare party

It delegates a health element to a healthcare party (By current healthcare party). Returns the element with new delegations.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val healthElementId : kotlin.String = healthElementId_example // kotlin.String | 
val delegationDto : kotlin.collections.List<DelegationDto> =  // kotlin.collections.List<DelegationDto> | 
try {
    val result : HealthElementDto = apiInstance.newHealthElementDelegations(healthElementId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#newHealthElementDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#newHealthElementDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthElementId** | **kotlin.String**|  |
 **delegationDto** | [**kotlin.collections.List&lt;DelegationDto&gt;**](DelegationDto.md)|  |

### Return type

[**HealthElementDto**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setHealthElementsDelegations"></a>
# **setHealthElementsDelegations**
> kotlin.collections.List&lt;HealthElementDto&gt; setHealthElementsDelegations(icureStubDto)

Update delegations in healthElements.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = HelementApi()
val icureStubDto : kotlin.collections.List<IcureStubDto> =  // kotlin.collections.List<IcureStubDto> | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.setHealthElementsDelegations(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling HelementApi#setHealthElementsDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling HelementApi#setHealthElementsDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **icureStubDto** | [**kotlin.collections.List&lt;IcureStubDto&gt;**](IcureStubDto.md)|  |

### Return type

[**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

