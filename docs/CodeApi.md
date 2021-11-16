# CodeApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createCode**](CodeApi.md#createCode) | **POST** /rest/v1/code | Create a code
[**filterCodesBy**](CodeApi.md#filterCodesBy) | **POST** /rest/v1/code/filter | Filter codes
[**findCodeTypes**](CodeApi.md#findCodeTypes) | **GET** /rest/v1/code/codetype/byRegionType | Get list of code types by region and type.
[**findCodes**](CodeApi.md#findCodes) | **GET** /rest/v1/code/byRegionTypeCode | Gets list of codes by code, type and version
[**findPaginatedCodes**](CodeApi.md#findPaginatedCodes) | **GET** /rest/v1/code | Gets paginated list of codes by code, type and version.
[**findPaginatedCodesByLabel**](CodeApi.md#findPaginatedCodesByLabel) | **GET** /rest/v1/code/byLabel | Get paginated list of codes by code, type and version.
[**findPaginatedCodesWithLink**](CodeApi.md#findPaginatedCodesWithLink) | **GET** /rest/v1/code/link/{linkType} | Gets paginated list of codes by link and link type.
[**findTagTypes**](CodeApi.md#findTagTypes) | **GET** /rest/v1/code/tagtype/byRegionType | Gets list of tag types by region and type.
[**getCode**](CodeApi.md#getCode) | **GET** /rest/v1/code/{codeId} | Get a code by id
[**getCodeWithParts**](CodeApi.md#getCodeWithParts) | **GET** /rest/v1/code/{type}/{code}/{version} | Get a code
[**getCodes**](CodeApi.md#getCodes) | **GET** /rest/v1/code/byIds/{codeIds} | Gets a list of codes by ids
[**modifyCode**](CodeApi.md#modifyCode) | **PUT** /rest/v1/code | Modify a code


<a name="createCode"></a>
# **createCode**
> CodeDto createCode(codeDto)

Create a code

Create a code entity. Fields Type, Code and Version are required.

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

<a name="findCodeTypes"></a>
# **findCodeTypes**
> kotlin.collections.List&lt;kotlin.String&gt; findCodeTypes(region, type)

Get list of code types by region and type.

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
    val result : kotlin.collections.List<kotlin.String> = apiInstance.findCodeTypes(region, type)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#findCodeTypes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#findCodeTypes")
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

<a name="findCodes"></a>
# **findCodes**
> kotlin.collections.List&lt;CodeDto&gt; findCodes(region, type, code, version)

Gets list of codes by code, type and version

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
    val result : kotlin.collections.List<CodeDto> = apiInstance.findCodes(region, type, code, version)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#findCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#findCodes")
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

<a name="findPaginatedCodes"></a>
# **findPaginatedCodes**
> PaginatedListCodeDto findPaginatedCodes(region, type, code, version, startKey, startDocumentId, limit)

Gets paginated list of codes by code, type and version.

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
    val result : PaginatedListCodeDto = apiInstance.findPaginatedCodes(region, type, code, version, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#findPaginatedCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#findPaginatedCodes")
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

<a name="findPaginatedCodesByLabel"></a>
# **findPaginatedCodesByLabel**
> PaginatedListCodeDto findPaginatedCodesByLabel(region, types, language, label, startKey, startDocumentId, limit)

Get paginated list of codes by code, type and version.

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
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A code document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListCodeDto = apiInstance.findPaginatedCodesByLabel(region, types, language, label, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#findPaginatedCodesByLabel")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#findPaginatedCodesByLabel")
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

<a name="findPaginatedCodesWithLink"></a>
# **findPaginatedCodesWithLink**
> PaginatedListCodeDto findPaginatedCodesWithLink(linkType, linkedId, startKey, startDocumentId, limit)

Gets paginated list of codes by link and link type.

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
    val result : PaginatedListCodeDto = apiInstance.findPaginatedCodesWithLink(linkType, linkedId, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#findPaginatedCodesWithLink")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#findPaginatedCodesWithLink")
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

<a name="findTagTypes"></a>
# **findTagTypes**
> kotlin.collections.List&lt;kotlin.String&gt; findTagTypes(region, type)

Gets list of tag types by region and type.

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
    val result : kotlin.collections.List<kotlin.String> = apiInstance.findTagTypes(region, type)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling CodeApi#findTagTypes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling CodeApi#findTagTypes")
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

<a name="getCode"></a>
# **getCode**
> CodeDto getCode(codeId)

Get a code by id

Get a code based on its id

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

Get a code based on (type, code, version) as query strings. (type, code, version) is unique.

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
> kotlin.collections.List&lt;CodeDto&gt; getCodes(codeIds)

Gets a list of codes by ids

Get a list of codes by ids/keys. Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = CodeApi()
val codeIds : kotlin.String = codeIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<CodeDto> = apiInstance.getCodes(codeIds)
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
 **codeIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;CodeDto&gt;**](CodeDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
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

