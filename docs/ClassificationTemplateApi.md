# ClassificationTemplateApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createClassificationTemplate**](ClassificationTemplateApi.md#createClassificationTemplate) | **POST** /rest/v2/classificationTemplate | Create a classification Template with the current user
[**deleteClassificationTemplates**](ClassificationTemplateApi.md#deleteClassificationTemplates) | **POST** /rest/v2/classificationTemplate/delete/batch | Delete classification Templates.
[**findClassificationTemplatesBy**](ClassificationTemplateApi.md#findClassificationTemplatesBy) | **GET** /rest/v2/classificationTemplate | List all classification templates with pagination
[**getClassificationTemplate**](ClassificationTemplateApi.md#getClassificationTemplate) | **GET** /rest/v2/classificationTemplate/{classificationTemplateId} | Get a classification Template
[**getClassificationTemplateByIds**](ClassificationTemplateApi.md#getClassificationTemplateByIds) | **GET** /rest/v2/classificationTemplate/byIds/{ids} | Get a list of classifications Templates
[**listClassificationTemplatesByHCPartyPatientForeignKeys**](ClassificationTemplateApi.md#listClassificationTemplatesByHCPartyPatientForeignKeys) | **GET** /rest/v2/classificationTemplate/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
[**modifyClassificationTemplate**](ClassificationTemplateApi.md#modifyClassificationTemplate) | **PUT** /rest/v2/classificationTemplate | Modify a classification Template
[**newClassificationTemplateDelegations**](ClassificationTemplateApi.md#newClassificationTemplateDelegations) | **POST** /rest/v2/classificationTemplate/{classificationTemplateId}/delegate | Delegates a classification Template to a healthcare party


<a name="createClassificationTemplate"></a>
# **createClassificationTemplate**
> ClassificationTemplateDto createClassificationTemplate(classificationTemplateDto)

Create a classification Template with the current user

Returns an instance of created classification Template.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationTemplateApi()
val classificationTemplateDto : ClassificationTemplateDto =  // ClassificationTemplateDto | 
try {
    val result : ClassificationTemplateDto = apiInstance.createClassificationTemplate(classificationTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationTemplateApi#createClassificationTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationTemplateApi#createClassificationTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationTemplateDto** | [**ClassificationTemplateDto**](ClassificationTemplateDto.md)|  |

### Return type

[**ClassificationTemplateDto**](ClassificationTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteClassificationTemplates"></a>
# **deleteClassificationTemplates**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteClassificationTemplates(listOfIdsDto)

Delete classification Templates.

Response is a set containing the ID&#39;s of deleted classification Templates.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationTemplateApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteClassificationTemplates(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationTemplateApi#deleteClassificationTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationTemplateApi#deleteClassificationTemplates")
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

<a name="findClassificationTemplatesBy"></a>
# **findClassificationTemplatesBy**
> PaginatedListClassificationTemplateDto findClassificationTemplatesBy(startKey, startDocumentId, limit)

List all classification templates with pagination

Returns a list of classification templates.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationTemplateApi()
val startKey : kotlin.String = startKey_example // kotlin.String | A label
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | An classification template document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListClassificationTemplateDto = apiInstance.findClassificationTemplatesBy(startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationTemplateApi#findClassificationTemplatesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationTemplateApi#findClassificationTemplatesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startKey** | **kotlin.String**| A label | [optional]
 **startDocumentId** | **kotlin.String**| An classification template document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListClassificationTemplateDto**](PaginatedListClassificationTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getClassificationTemplate"></a>
# **getClassificationTemplate**
> ClassificationTemplateDto getClassificationTemplate(classificationTemplateId)

Get a classification Template

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationTemplateApi()
val classificationTemplateId : kotlin.String = classificationTemplateId_example // kotlin.String | 
try {
    val result : ClassificationTemplateDto = apiInstance.getClassificationTemplate(classificationTemplateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationTemplateApi#getClassificationTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationTemplateApi#getClassificationTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationTemplateId** | **kotlin.String**|  |

### Return type

[**ClassificationTemplateDto**](ClassificationTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getClassificationTemplateByIds"></a>
# **getClassificationTemplateByIds**
> kotlin.collections.List&lt;ClassificationTemplateDto&gt; getClassificationTemplateByIds(ids)

Get a list of classifications Templates

Ids are seperated by a coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationTemplateApi()
val ids : kotlin.String = ids_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ClassificationTemplateDto> = apiInstance.getClassificationTemplateByIds(ids)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationTemplateApi#getClassificationTemplateByIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationTemplateApi#getClassificationTemplateByIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ids** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ClassificationTemplateDto&gt;**](ClassificationTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listClassificationTemplatesByHCPartyPatientForeignKeys"></a>
# **listClassificationTemplatesByHCPartyPatientForeignKeys**
> kotlin.collections.List&lt;ClassificationTemplateDto&gt; listClassificationTemplatesByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)

List classification Templates found By Healthcare Party and secret foreign keyelementIds.

Keys hast to delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationTemplateApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ClassificationTemplateDto> = apiInstance.listClassificationTemplatesByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationTemplateApi#listClassificationTemplatesByHCPartyPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationTemplateApi#listClassificationTemplatesByHCPartyPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ClassificationTemplateDto&gt;**](ClassificationTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyClassificationTemplate"></a>
# **modifyClassificationTemplate**
> ClassificationTemplateDto modifyClassificationTemplate(classificationTemplateDto)

Modify a classification Template

Returns the modified classification Template.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationTemplateApi()
val classificationTemplateDto : ClassificationTemplateDto =  // ClassificationTemplateDto | 
try {
    val result : ClassificationTemplateDto = apiInstance.modifyClassificationTemplate(classificationTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationTemplateApi#modifyClassificationTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationTemplateApi#modifyClassificationTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationTemplateDto** | [**ClassificationTemplateDto**](ClassificationTemplateDto.md)|  |

### Return type

[**ClassificationTemplateDto**](ClassificationTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="newClassificationTemplateDelegations"></a>
# **newClassificationTemplateDelegations**
> ClassificationTemplateDto newClassificationTemplateDelegations(classificationTemplateId, delegationDto)

Delegates a classification Template to a healthcare party

It delegates a classification Template to a healthcare party (By current healthcare party). Returns the element with new delegations.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = ClassificationTemplateApi()
val classificationTemplateId : kotlin.String = classificationTemplateId_example // kotlin.String | 
val delegationDto : kotlin.collections.List<DelegationDto> =  // kotlin.collections.List<DelegationDto> | 
try {
    val result : ClassificationTemplateDto = apiInstance.newClassificationTemplateDelegations(classificationTemplateId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling ClassificationTemplateApi#newClassificationTemplateDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling ClassificationTemplateApi#newClassificationTemplateDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationTemplateId** | **kotlin.String**|  |
 **delegationDto** | [**kotlin.collections.List&lt;DelegationDto&gt;**](DelegationDto.md)|  |

### Return type

[**ClassificationTemplateDto**](ClassificationTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

