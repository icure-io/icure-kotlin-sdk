# ClassificationApi

All URIs are relative to *https://kraken.svc.icure.cloud*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createClassification**](ClassificationApi.md#createClassification) | **POST** /rest/v2/classification | Create a classification with the current user
[**deleteClassifications**](ClassificationApi.md#deleteClassifications) | **POST** /rest/v2/classification/delete/batch | Delete classification Templates.
[**findClassificationsByHCPartyPatientForeignKeys**](ClassificationApi.md#findClassificationsByHCPartyPatientForeignKeys) | **GET** /rest/v2/classification/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
[**getClassification**](ClassificationApi.md#getClassification) | **GET** /rest/v2/classification/{classificationId} | Get a classification Template
[**getClassificationByHcPartyId**](ClassificationApi.md#getClassificationByHcPartyId) | **GET** /rest/v2/classification/byIds/{ids} | Get a list of classifications
[**modifyClassification**](ClassificationApi.md#modifyClassification) | **PUT** /rest/v2/classification | Modify a classification Template
[**newClassificationDelegations**](ClassificationApi.md#newClassificationDelegations) | **POST** /rest/v2/classification/{classificationId}/delegate | Delegates a classification to a healthcare party
[**setClassificationsDelegations**](ClassificationApi.md#setClassificationsDelegations) | **POST** /rest/v2/classification/delegations | Update delegations in classification


<a name="createClassification"></a>
# **createClassification**
> ClassificationDto createClassification(classificationDto)

Create a classification with the current user

Returns an instance of created classification Template.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val classificationDto : ClassificationDto =  // ClassificationDto | 
try {
    val result : ClassificationDto = apiInstance.createClassification(classificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#createClassification")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#createClassification")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationDto** | [**ClassificationDto**](ClassificationDto.md)|  |

### Return type

[**ClassificationDto**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteClassifications"></a>
# **deleteClassifications**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteClassifications(listOfIdsDto)

Delete classification Templates.

Response is a set containing the ID&#39;s of deleted classification Templates.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteClassifications(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#deleteClassifications")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#deleteClassifications")
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

<a name="findClassificationsByHCPartyPatientForeignKeys"></a>
# **findClassificationsByHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;ClassificationDto&gt; findClassificationsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)

List classification Templates found By Healthcare Party and secret foreign keyelementIds.

Keys hast to delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ClassificationDto> = apiInstance.findClassificationsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#findClassificationsByHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#findClassificationsByHCPartyPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ClassificationDto&gt;**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getClassification"></a>
# **getClassification**
> ClassificationDto getClassification(classificationId)

Get a classification Template

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val classificationId : kotlin.String = classificationId_example // kotlin.String | 
try {
    val result : ClassificationDto = apiInstance.getClassification(classificationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#getClassification")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#getClassification")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationId** | **kotlin.String**|  |

### Return type

[**ClassificationDto**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getClassificationByHcPartyId"></a>
# **getClassificationByHcPartyId**
> kotlin.collections.List&lt;ClassificationDto&gt; getClassificationByHcPartyId(ids)

Get a list of classifications

Ids are seperated by a coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val ids : kotlin.String = ids_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ClassificationDto> = apiInstance.getClassificationByHcPartyId(ids)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#getClassificationByHcPartyId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#getClassificationByHcPartyId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ids** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ClassificationDto&gt;**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyClassification"></a>
# **modifyClassification**
> ClassificationDto modifyClassification(classificationDto)

Modify a classification Template

Returns the modified classification Template.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val classificationDto : ClassificationDto =  // ClassificationDto | 
try {
    val result : ClassificationDto = apiInstance.modifyClassification(classificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#modifyClassification")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#modifyClassification")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationDto** | [**ClassificationDto**](ClassificationDto.md)|  |

### Return type

[**ClassificationDto**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="newClassificationDelegations"></a>
# **newClassificationDelegations**
> ClassificationDto newClassificationDelegations(classificationId, delegationDto)

Delegates a classification to a healthcare party

It delegates a classification to a healthcare party (By current healthcare party). Returns the element with new delegations.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val classificationId : kotlin.String = classificationId_example // kotlin.String | 
val delegationDto : kotlin.collections.List<DelegationDto> =  // kotlin.collections.List<DelegationDto> | 
try {
    val result : ClassificationDto = apiInstance.newClassificationDelegations(classificationId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#newClassificationDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#newClassificationDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationId** | **kotlin.String**|  |
 **delegationDto** | [**kotlin.collections.List&lt;DelegationDto&gt;**](DelegationDto.md)|  |

### Return type

[**ClassificationDto**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setClassificationsDelegations"></a>
# **setClassificationsDelegations**
> kotlin.collections.List&lt;IcureStubDto&gt; setClassificationsDelegations(icureStubDto)

Update delegations in classification

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val icureStubDto : kotlin.collections.List<IcureStubDto> =  // kotlin.collections.List<IcureStubDto> | 
try {
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.setClassificationsDelegations(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#setClassificationsDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#setClassificationsDelegations")
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

