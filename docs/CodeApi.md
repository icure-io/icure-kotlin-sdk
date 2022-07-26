# CodeApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createCode**](CodeApi.md#createCode) | **POST** /rest/v2/code | Create a Code
[**createCodes**](CodeApi.md#createCodes) | **POST** /rest/v2/code/batch | Create a batch of codes
[**filterCodesBy**](CodeApi.md#filterCodesBy) | **POST** /rest/v2/code/filter | Filter codes 
[**findCodesByLabel**](CodeApi.md#findCodesByLabel) | **GET** /rest/v2/code/byLabel | Finding codes by code, type and version with pagination.
[**findCodesByLink**](CodeApi.md#findCodesByLink) | **GET** /rest/v2/code/byLink/{linkType} | Finding codes by code, type and version with pagination.
[**findCodesByType**](CodeApi.md#findCodesByType) | **GET** /rest/v2/code | Finding codes by code, type and version with pagination.
[**getCode**](CodeApi.md#getCode) | **GET** /rest/v2/code/{codeId} | Get a code
[**getCodeWithParts**](CodeApi.md#getCodeWithParts) | **GET** /rest/v2/code/{type}/{code}/{version} | Get a code
[**getCodes**](CodeApi.md#getCodes) | **POST** /rest/v2/code/byIds | Get a list of codes by ids
[**importCodes**](CodeApi.md#importCodes) | **POST** /rest/v2/code/{codeType} | Import codes
[**listCodeTypesBy**](CodeApi.md#listCodeTypesBy) | **GET** /rest/v2/code/codetype/byRegionType | Finding code types.
[**listCodesByRegionTypeCodeVersion**](CodeApi.md#listCodesByRegionTypeCodeVersion) | **GET** /rest/v2/code/byRegionTypeCode | Finding codes by code, type and version
[**listTagTypesBy**](CodeApi.md#listTagTypesBy) | **GET** /rest/v2/code/tagtype/byRegionType | Finding tag types.
[**matchCodesBy**](CodeApi.md#matchCodesBy) | **POST** /rest/v2/code/match | Get ids of code matching the provided filter for the current user (HcParty) 
[**modifyCode**](CodeApi.md#modifyCode) | **PUT** /rest/v2/code | Modify a code
[**modifyCodes**](CodeApi.md#modifyCodes) | **PUT** /rest/v2/code/batch | Modify a batch of codes


<a name="createCode"></a>
# **createCode**
> CodeDto createCode(codeDto)

Create a Code

Type, Code and Version are required.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val codeDto : CodeDto =  // CodeDto | 
try {
    val result : CodeDto = apiInstance.createCode(codeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#createCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#createCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **codeDto** | [**CodeDto**](CodeDto.md)|  |

### Return type

[**CodeDto**](CodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createCodes"></a>
# **createCodes**
> kotlin.collections.List&lt;CodeDto&gt; createCodes(codeDto)

Create a batch of codes

Create a batch of code entities. Fields Type, Code and Version are required for each code.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val codeDto : kotlin.collections.List<CodeDto> =  // kotlin.collections.List<CodeDto> | 
try {
    val result : kotlin.collections.List<CodeDto> = apiInstance.createCodes(codeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#createCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#createCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **codeDto** | [**kotlin.collections.List&lt;CodeDto&gt;**](CodeDto.md)|  |

### Return type

[**kotlin.collections.List&lt;CodeDto&gt;**](CodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="filterCodesBy"></a>
# **filterCodesBy**
> PaginatedListCodeDto filterCodesBy(startKey, startDocumentId, limit, skip, sort, desc, filterChainCode)

Filter codes 

Returns a list of codes along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination, depends on the filters used
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val skip : kotlin.Int = 56 // kotlin.Int | Skip rows
val sort : kotlin.String = sort_example // kotlin.String | Sort key
val desc : kotlin.Boolean = true // kotlin.Boolean | Descending
val filterChainCode : FilterChainCode =  // FilterChainCode | 
try {
    val result : PaginatedListCodeDto = apiInstance.filterCodesBy(startKey, startDocumentId, limit, skip, sort, desc, filterChainCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#filterCodesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#filterCodesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startKey** | **kotlin.String**| The start key for pagination, depends on the filters used | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]
 **skip** | **kotlin.Int**| Skip rows | [optional]
 **sort** | **kotlin.String**| Sort key | [optional]
 **desc** | **kotlin.Boolean**| Descending | [optional]
 **filterChainCode** | [**FilterChainCode**](FilterChainCode.md)|  | [optional]

### Return type

[**PaginatedListCodeDto**](PaginatedListCodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findCodesByLabel"></a>
# **findCodesByLabel**
> PaginatedListCodeDto findCodesByLabel(region, types, language, label, version, startKey, startDocumentId, limit)

Finding codes by code, type and version with pagination.

Returns a list of codes matched with given input. If several types are provided, pagination is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val region : kotlin.String = region_example // kotlin.String | 
val types : kotlin.String = types_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val label : kotlin.String = label_example // kotlin.String | 
val version : kotlin.String = version_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A code document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListCodeDto = apiInstance.findCodesByLabel(region, types, language, label, version, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#findCodesByLabel")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#findCodesByLabel")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **region** | **kotlin.String**|  | [optional]
 **types** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **label** | **kotlin.String**|  | [optional]
 **version** | **kotlin.String**|  | [optional]
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A code document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListCodeDto**](PaginatedListCodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findCodesByLink"></a>
# **findCodesByLink**
> PaginatedListCodeDto findCodesByLink(linkType, linkedId, startKey, startDocumentId, limit)

Finding codes by code, type and version with pagination.

Returns a list of codes matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val linkType : kotlin.String = linkType_example // kotlin.String | 
val linkedId : kotlin.String = linkedId_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A code document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListCodeDto = apiInstance.findCodesByLink(linkType, linkedId, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#findCodesByLink")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#findCodesByLink")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **linkType** | **kotlin.String**|  |
 **linkedId** | **kotlin.String**|  | [optional]
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A code document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListCodeDto**](PaginatedListCodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findCodesByType"></a>
# **findCodesByType**
> PaginatedListCodeDto findCodesByType(region, type, code, version, startKey, startDocumentId, limit)

Finding codes by code, type and version with pagination.

Returns a list of codes matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val region : kotlin.String = region_example // kotlin.String | 
val type : kotlin.String = type_example // kotlin.String | 
val code : kotlin.String = code_example // kotlin.String | 
val version : kotlin.String = version_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A code document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListCodeDto = apiInstance.findCodesByType(region, type, code, version, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#findCodesByType")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#findCodesByType")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **region** | **kotlin.String**|  | [optional]
 **type** | **kotlin.String**|  | [optional]
 **code** | **kotlin.String**|  | [optional]
 **version** | **kotlin.String**|  | [optional]
 **startKey** | **kotlin.String**| The start key for pagination | [optional]
 **startDocumentId** | **kotlin.String**| A code document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListCodeDto**](PaginatedListCodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCode"></a>
# **getCode**
> CodeDto getCode(codeId)

Get a code

Get a code based on ID or (code,type,version) as query strings. (code,type,version) is unique.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val codeId : kotlin.String = codeId_example // kotlin.String | Code id
try {
    val result : CodeDto = apiInstance.getCode(codeId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#getCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#getCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **codeId** | **kotlin.String**| Code id |

### Return type

[**CodeDto**](CodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCodeWithParts"></a>
# **getCodeWithParts**
> CodeDto getCodeWithParts(type, code, version)

Get a code

Get a code based on ID or (code,type,version) as query strings. (code,type,version) is unique.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val type : kotlin.String = type_example // kotlin.String | Code type
val code : kotlin.String = code_example // kotlin.String | Code code
val version : kotlin.String = version_example // kotlin.String | Code version
try {
    val result : CodeDto = apiInstance.getCodeWithParts(type, code, version)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#getCodeWithParts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#getCodeWithParts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **type** | **kotlin.String**| Code type |
 **code** | **kotlin.String**| Code code |
 **version** | **kotlin.String**| Code version |

### Return type

[**CodeDto**](CodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCodes"></a>
# **getCodes**
> kotlin.collections.List&lt;CodeDto&gt; getCodes(listOfIdsDto)

Get a list of codes by ids

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<CodeDto> = apiInstance.getCodes(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#getCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#getCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;CodeDto&gt;**](CodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="importCodes"></a>
# **importCodes**
> kotlin.Any importCodes(codeType)

Import codes

Import codes from the resources XML file depending on the passed pathVariable

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val codeType : kotlin.String = codeType_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.importCodes(codeType)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#importCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#importCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **codeType** | **kotlin.String**|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listCodeTypesBy"></a>
# **listCodeTypesBy**
> kotlin.collections.List&lt;kotlin.String&gt; listCodeTypesBy(region, type)

Finding code types.

Returns a list of code types matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val region : kotlin.String = region_example // kotlin.String | Code region
val type : kotlin.String = type_example // kotlin.String | Code type
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.listCodeTypesBy(region, type)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#listCodeTypesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#listCodeTypesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **region** | **kotlin.String**| Code region | [optional]
 **type** | **kotlin.String**| Code type | [optional]

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listCodesByRegionTypeCodeVersion"></a>
# **listCodesByRegionTypeCodeVersion**
> kotlin.collections.List&lt;CodeDto&gt; listCodesByRegionTypeCodeVersion(region, type, code, version)

Finding codes by code, type and version

Returns a list of codes matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val region : kotlin.String = region_example // kotlin.String | Code region
val type : kotlin.String = type_example // kotlin.String | Code type
val code : kotlin.String = code_example // kotlin.String | Code code
val version : kotlin.String = version_example // kotlin.String | Code version
try {
    val result : kotlin.collections.List<CodeDto> = apiInstance.listCodesByRegionTypeCodeVersion(region, type, code, version)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#listCodesByRegionTypeCodeVersion")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#listCodesByRegionTypeCodeVersion")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **region** | **kotlin.String**| Code region | [optional]
 **type** | **kotlin.String**| Code type | [optional]
 **code** | **kotlin.String**| Code code | [optional]
 **version** | **kotlin.String**| Code version | [optional]

### Return type

[**kotlin.collections.List&lt;CodeDto&gt;**](CodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listTagTypesBy"></a>
# **listTagTypesBy**
> kotlin.collections.List&lt;kotlin.String&gt; listTagTypesBy(region, type)

Finding tag types.

Returns a list of tag types matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val region : kotlin.String = region_example // kotlin.String | Code region
val type : kotlin.String = type_example // kotlin.String | Code type
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.listTagTypesBy(region, type)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#listTagTypesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#listTagTypesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **region** | **kotlin.String**| Code region | [optional]
 **type** | **kotlin.String**| Code type | [optional]

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="matchCodesBy"></a>
# **matchCodesBy**
> kotlin.collections.List&lt;kotlin.String&gt; matchCodesBy(abstractFilterDtoCode)

Get ids of code matching the provided filter for the current user (HcParty) 

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val abstractFilterDtoCode : AbstractFilterDtoCode =  // AbstractFilterDtoCode | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.matchCodesBy(abstractFilterDtoCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#matchCodesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#matchCodesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **abstractFilterDtoCode** | [**AbstractFilterDtoCode**](AbstractFilterDtoCode.md)|  |

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyCode"></a>
# **modifyCode**
> CodeDto modifyCode(codeDto)

Modify a code

Modification of (type, code, version) is not allowed.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val codeDto : CodeDto =  // CodeDto | 
try {
    val result : CodeDto = apiInstance.modifyCode(codeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#modifyCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#modifyCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **codeDto** | [**CodeDto**](CodeDto.md)|  |

### Return type

[**CodeDto**](CodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyCodes"></a>
# **modifyCodes**
> kotlin.collections.List&lt;CodeDto&gt; modifyCodes(codeDto)

Modify a batch of codes

Modification of (type, code, version) is not allowed.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val codeDto : kotlin.collections.List<CodeDto> =  // kotlin.collections.List<CodeDto> | 
try {
    val result : kotlin.collections.List<CodeDto> = apiInstance.modifyCodes(codeDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#modifyCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#modifyCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **codeDto** | [**kotlin.collections.List&lt;CodeDto&gt;**](CodeDto.md)|  |

### Return type

[**kotlin.collections.List&lt;CodeDto&gt;**](CodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

