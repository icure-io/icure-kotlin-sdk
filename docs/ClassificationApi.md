# ClassificationApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createClassification**](ClassificationApi.md#createClassification) | **POST** /rest/v2/classification | Create a classification with the current user
[**createClassification1**](ClassificationApi.md#createClassification1) | **POST** /rest/v1/classification | Create a classification with the current user
[**deleteClassifications**](ClassificationApi.md#deleteClassifications) | **POST** /rest/v2/classification/delete/batch | Delete classification Templates.
[**deleteClassifications1**](ClassificationApi.md#deleteClassifications1) | **DELETE** /rest/v1/classification/{classificationIds} | Delete classification Templates.
[**findClassificationsByHCPartyPatientForeignKeys**](ClassificationApi.md#findClassificationsByHCPartyPatientForeignKeys) | **GET** /rest/v2/classification/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
[**findClassificationsByHCPartyPatientForeignKeys1**](ClassificationApi.md#findClassificationsByHCPartyPatientForeignKeys1) | **GET** /rest/v1/classification/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
[**getClassification**](ClassificationApi.md#getClassification) | **GET** /rest/v2/classification/{classificationId} | Get a classification Template
[**getClassification1**](ClassificationApi.md#getClassification1) | **GET** /rest/v1/classification/{classificationId} | Get a classification Template
[**getClassificationByHcPartyId**](ClassificationApi.md#getClassificationByHcPartyId) | **GET** /rest/v2/classification/byIds/{ids} | Get a list of classifications
[**getClassificationByHcPartyId1**](ClassificationApi.md#getClassificationByHcPartyId1) | **GET** /rest/v1/classification/byIds/{ids} | Get a list of classifications
[**modifyClassification**](ClassificationApi.md#modifyClassification) | **PUT** /rest/v2/classification | Modify a classification Template
[**modifyClassification1**](ClassificationApi.md#modifyClassification1) | **PUT** /rest/v1/classification | Modify a classification Template
[**newClassificationDelegations**](ClassificationApi.md#newClassificationDelegations) | **POST** /rest/v2/classification/{classificationId}/delegate | Delegates a classification to a healthcare party
[**newClassificationDelegations1**](ClassificationApi.md#newClassificationDelegations1) | **POST** /rest/v1/classification/{classificationId}/delegate | Delegates a classification to a healthcare party
[**setClassificationsDelegations**](ClassificationApi.md#setClassificationsDelegations) | **POST** /rest/v2/classification/delegations | Update delegations in classification
[**setClassificationsDelegations1**](ClassificationApi.md#setClassificationsDelegations1) | **POST** /rest/v1/classification/delegations | Update delegations in classification


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

<a name="createClassification1"></a>
# **createClassification1**
> ClassificationDto createClassification1(classificationDto)

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
    val result : ClassificationDto = apiInstance.createClassification1(classificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#createClassification1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#createClassification1")
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

<a name="deleteClassifications1"></a>
# **deleteClassifications1**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteClassifications1(classificationIds)

Delete classification Templates.

Response is a set containing the ID&#39;s of deleted classification Templates.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val classificationIds : kotlin.String = classificationIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteClassifications1(classificationIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#deleteClassifications1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#deleteClassifications1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
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

<a name="findClassificationsByHCPartyPatientForeignKeys1"></a>
# **findClassificationsByHCPartyPatientForeignKeys1**
> kotlin.collections.List&lt;ClassificationDto&gt; findClassificationsByHCPartyPatientForeignKeys1(hcPartyId, secretFKeys)

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
    val result : kotlin.collections.List<ClassificationDto> = apiInstance.findClassificationsByHCPartyPatientForeignKeys1(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#findClassificationsByHCPartyPatientForeignKeys1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#findClassificationsByHCPartyPatientForeignKeys1")
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

<a name="getClassification1"></a>
# **getClassification1**
> ClassificationDto getClassification1(classificationId)

Get a classification Template

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationApi()
val classificationId : kotlin.String = classificationId_example // kotlin.String | 
try {
    val result : ClassificationDto = apiInstance.getClassification1(classificationId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#getClassification1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#getClassification1")
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

<a name="getClassificationByHcPartyId1"></a>
# **getClassificationByHcPartyId1**
> kotlin.collections.List&lt;ClassificationDto&gt; getClassificationByHcPartyId1(ids)

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
    val result : kotlin.collections.List<ClassificationDto> = apiInstance.getClassificationByHcPartyId1(ids)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#getClassificationByHcPartyId1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#getClassificationByHcPartyId1")
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

<a name="modifyClassification1"></a>
# **modifyClassification1**
> ClassificationDto modifyClassification1(classificationDto)

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
    val result : ClassificationDto = apiInstance.modifyClassification1(classificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#modifyClassification1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#modifyClassification1")
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

<a name="newClassificationDelegations1"></a>
# **newClassificationDelegations1**
> ClassificationDto newClassificationDelegations1(classificationId, delegationDto)

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
    val result : ClassificationDto = apiInstance.newClassificationDelegations1(classificationId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#newClassificationDelegations1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#newClassificationDelegations1")
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

<a name="setClassificationsDelegations1"></a>
# **setClassificationsDelegations1**
> kotlin.collections.List&lt;IcureStubDto&gt; setClassificationsDelegations1(icureStubDto)

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
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.setClassificationsDelegations1(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationApi#setClassificationsDelegations1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationApi#setClassificationsDelegations1")
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

