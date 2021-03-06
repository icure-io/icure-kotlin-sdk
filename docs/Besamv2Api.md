# Besamv2Api

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**findAmpsByDmppCode**](Besamv2Api.md#findAmpsByDmppCode) | **GET** /rest/v2/be_samv2/amp/byDmppCode/{dmppCode} | Finding AMPs by dmpp code
[**findPaginatedAmpsByAtc**](Besamv2Api.md#findPaginatedAmpsByAtc) | **GET** /rest/v2/be_samv2/vmp/byAtc/{atcCode} | Finding AMPs by atc code with pagination.
[**findPaginatedAmpsByGroupCode**](Besamv2Api.md#findPaginatedAmpsByGroupCode) | **GET** /rest/v2/be_samv2/amp/byGroupCode/{vmpgCode} | Finding AMPs by group with pagination.
[**findPaginatedAmpsByGroupId**](Besamv2Api.md#findPaginatedAmpsByGroupId) | **GET** /rest/v2/be_samv2/amp/byGroupId/{vmpgId} | Finding AMPs by group with pagination.
[**findPaginatedAmpsByLabel**](Besamv2Api.md#findPaginatedAmpsByLabel) | **GET** /rest/v2/be_samv2/amp | Finding AMPs by label with pagination.
[**findPaginatedAmpsByVmpCode**](Besamv2Api.md#findPaginatedAmpsByVmpCode) | **GET** /rest/v2/be_samv2/amp/byVmpCode/{vmpCode} | Finding AMPs by vmp code with pagination.
[**findPaginatedAmpsByVmpId**](Besamv2Api.md#findPaginatedAmpsByVmpId) | **GET** /rest/v2/be_samv2/amp/byVmpId/{vmpId} | Finding AMPs by vmp id with pagination.
[**findPaginatedNmpsByLabel**](Besamv2Api.md#findPaginatedNmpsByLabel) | **GET** /rest/v2/be_samv2/nmp | Finding NMPs by label with pagination.
[**findPaginatedVmpGroupsByLabel**](Besamv2Api.md#findPaginatedVmpGroupsByLabel) | **GET** /rest/v2/be_samv2/vmpgroup | Finding VMP groups by language label with pagination.
[**findPaginatedVmpGroupsByVmpGroupCode**](Besamv2Api.md#findPaginatedVmpGroupsByVmpGroupCode) | **GET** /rest/v2/be_samv2/vmpgroup/byGroupCode/{vmpgCode} | Finding VMP groups by cmpgCode with pagination.
[**findPaginatedVmpsByGroupCode**](Besamv2Api.md#findPaginatedVmpsByGroupCode) | **GET** /rest/v2/be_samv2/vmp/byGroupCode/{vmpgCode} | Finding VMPs by group with pagination.
[**findPaginatedVmpsByGroupId**](Besamv2Api.md#findPaginatedVmpsByGroupId) | **GET** /rest/v2/be_samv2/vmp/byGroupId/{vmpgId} | Finding VMPs by group with pagination.
[**findPaginatedVmpsByLabel**](Besamv2Api.md#findPaginatedVmpsByLabel) | **GET** /rest/v2/be_samv2/vmp | Finding VMPs by label with pagination.
[**findPaginatedVmpsByVmpCode**](Besamv2Api.md#findPaginatedVmpsByVmpCode) | **GET** /rest/v2/be_samv2/vmp/byVmpCode/{vmpCode} | Finding VMPs by group with pagination.
[**findParagraphs**](Besamv2Api.md#findParagraphs) | **GET** /rest/v2/be_samv2/chap/search/{searchString}/{language} | 
[**findParagraphsWithCnk**](Besamv2Api.md#findParagraphsWithCnk) | **GET** /rest/v2/be_samv2/chap/bycnk/{cnk}/{language} | 
[**getAddedDocument**](Besamv2Api.md#getAddedDocument) | **GET** /rest/v2/be_samv2/chap/{chapterName}/{paragraphName}/{verseSeq}/addeddoc/{docSeq}/{language} | 
[**getAmpsForParagraph**](Besamv2Api.md#getAmpsForParagraph) | **GET** /rest/v2/be_samv2/chap/amps/{chapterName}/{paragraphName} | 
[**getSamVersion**](Besamv2Api.md#getSamVersion) | **GET** /rest/v2/be_samv2/v | Get Samv2 version.
[**getVersesHierarchy**](Besamv2Api.md#getVersesHierarchy) | **GET** /rest/v2/be_samv2/chap/verse/{chapterName}/{paragraphName} | 
[**getVtmNamesForParagraph**](Besamv2Api.md#getVtmNamesForParagraph) | **GET** /rest/v2/be_samv2/chap/vtms/{chapterName}/{paragraphName}/{language} | 
[**listAmpsByDmppCodes**](Besamv2Api.md#listAmpsByDmppCodes) | **POST** /rest/v2/be_samv2/amp/byDmppCodes | Finding AMPs by dmpp code
[**listAmpsByGroupCodes**](Besamv2Api.md#listAmpsByGroupCodes) | **POST** /rest/v2/be_samv2/amp/byGroupCodes | Finding AMPs by group.
[**listAmpsByGroupIds**](Besamv2Api.md#listAmpsByGroupIds) | **POST** /rest/v2/be_samv2/amp/byGroupIds | Finding AMPs by group.
[**listAmpsByVmpCodes**](Besamv2Api.md#listAmpsByVmpCodes) | **POST** /rest/v2/be_samv2/amp/byVmpCodes | Finding AMPs by vmp code.
[**listAmpsByVmpIds**](Besamv2Api.md#listAmpsByVmpIds) | **POST** /rest/v2/be_samv2/amp/byVmpIds | Finding AMPs by vmp id.
[**listNmpsByCnks**](Besamv2Api.md#listNmpsByCnks) | **POST** /rest/v2/be_samv2/nmp/byCnks | Finding NMPs by cnk id.
[**listPharmaceuticalForms**](Besamv2Api.md#listPharmaceuticalForms) | **GET** /rest/v2/be_samv2/pharmaform | List all pharmaceutical forms.
[**listSubstances**](Besamv2Api.md#listSubstances) | **GET** /rest/v2/be_samv2/substance | List all substances.
[**listVmpGroupsByVmpGroupCodes**](Besamv2Api.md#listVmpGroupsByVmpGroupCodes) | **POST** /rest/v2/be_samv2/vmpgroup/byGroupCodes | Finding AMPs by group.
[**listVmpsByGroupIds**](Besamv2Api.md#listVmpsByGroupIds) | **POST** /rest/v2/be_samv2/vmp/byGroupIds | Finding VMPs by group.
[**listVmpsByVmpCodes**](Besamv2Api.md#listVmpsByVmpCodes) | **POST** /rest/v2/be_samv2/vmp/byVmpCodes | Finding VMPs by group.


<a name="findAmpsByDmppCode"></a>
# **findAmpsByDmppCode**
> kotlin.collections.List&lt;AmpDto&gt; findAmpsByDmppCode(dmppCode)

Finding AMPs by dmpp code

Returns a list of amps matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val dmppCode : kotlin.String = dmppCode_example // kotlin.String | dmppCode
try {
    val result : kotlin.collections.List<AmpDto> = apiInstance.findAmpsByDmppCode(dmppCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findAmpsByDmppCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findAmpsByDmppCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **dmppCode** | **kotlin.String**| dmppCode |

### Return type

[**kotlin.collections.List&lt;AmpDto&gt;**](AmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedAmpsByAtc"></a>
# **findPaginatedAmpsByAtc**
> PaginatedListAmpDto findPaginatedAmpsByAtc(atcCode, startKey, startDocumentId, limit)

Finding AMPs by atc code with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val atcCode : kotlin.String = atcCode_example // kotlin.String | atcCode
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A amp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListAmpDto = apiInstance.findPaginatedAmpsByAtc(atcCode, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedAmpsByAtc")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedAmpsByAtc")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **atcCode** | **kotlin.String**| atcCode |
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A amp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListAmpDto**](PaginatedListAmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedAmpsByGroupCode"></a>
# **findPaginatedAmpsByGroupCode**
> PaginatedListAmpDto findPaginatedAmpsByGroupCode(vmpgCode, startKey, startDocumentId, limit)

Finding AMPs by group with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val vmpgCode : kotlin.String = vmpgCode_example // kotlin.String | vmpgCode
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A vmp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListAmpDto = apiInstance.findPaginatedAmpsByGroupCode(vmpgCode, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedAmpsByGroupCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedAmpsByGroupCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vmpgCode** | **kotlin.String**| vmpgCode |
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A vmp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListAmpDto**](PaginatedListAmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedAmpsByGroupId"></a>
# **findPaginatedAmpsByGroupId**
> PaginatedListAmpDto findPaginatedAmpsByGroupId(vmpgId, startKey, startDocumentId, limit)

Finding AMPs by group with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val vmpgId : kotlin.String = vmpgId_example // kotlin.String | vmpgCode
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A vmp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListAmpDto = apiInstance.findPaginatedAmpsByGroupId(vmpgId, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedAmpsByGroupId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedAmpsByGroupId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vmpgId** | **kotlin.String**| vmpgCode |
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A vmp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListAmpDto**](PaginatedListAmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedAmpsByLabel"></a>
# **findPaginatedAmpsByLabel**
> PaginatedListAmpDto findPaginatedAmpsByLabel(language, label, startKey, startDocumentId, limit)

Finding AMPs by label with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val language : kotlin.String = language_example // kotlin.String | language
val label : kotlin.String = label_example // kotlin.String | label
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | An amp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListAmpDto = apiInstance.findPaginatedAmpsByLabel(language, label, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedAmpsByLabel")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedAmpsByLabel")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **language** | **kotlin.String**| language | [optional]
 **label** | **kotlin.String**| label | [optional]
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| An amp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListAmpDto**](PaginatedListAmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedAmpsByVmpCode"></a>
# **findPaginatedAmpsByVmpCode**
> PaginatedListAmpDto findPaginatedAmpsByVmpCode(vmpCode, startKey, startDocumentId, limit)

Finding AMPs by vmp code with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val vmpCode : kotlin.String = vmpCode_example // kotlin.String | vmpCode
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A amp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListAmpDto = apiInstance.findPaginatedAmpsByVmpCode(vmpCode, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedAmpsByVmpCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedAmpsByVmpCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vmpCode** | **kotlin.String**| vmpCode |
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A amp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListAmpDto**](PaginatedListAmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedAmpsByVmpId"></a>
# **findPaginatedAmpsByVmpId**
> PaginatedListAmpDto findPaginatedAmpsByVmpId(vmpId, startKey, startDocumentId, limit)

Finding AMPs by vmp id with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val vmpId : kotlin.String = vmpId_example // kotlin.String | vmpgCode
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A amp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListAmpDto = apiInstance.findPaginatedAmpsByVmpId(vmpId, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedAmpsByVmpId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedAmpsByVmpId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vmpId** | **kotlin.String**| vmpgCode |
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A amp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListAmpDto**](PaginatedListAmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedNmpsByLabel"></a>
# **findPaginatedNmpsByLabel**
> PaginatedListNmpDto findPaginatedNmpsByLabel(language, label, startKey, startDocumentId, limit)

Finding NMPs by label with pagination.

Returns a paginated list of NMPs by matching label. Matches occur per word

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val language : kotlin.String = language_example // kotlin.String | language
val label : kotlin.String = label_example // kotlin.String | label
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A vmp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListNmpDto = apiInstance.findPaginatedNmpsByLabel(language, label, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedNmpsByLabel")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedNmpsByLabel")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **language** | **kotlin.String**| language | [optional]
 **label** | **kotlin.String**| label | [optional]
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A vmp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListNmpDto**](PaginatedListNmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedVmpGroupsByLabel"></a>
# **findPaginatedVmpGroupsByLabel**
> PaginatedListVmpGroupDto findPaginatedVmpGroupsByLabel(language, label, startKey, startDocumentId, limit)

Finding VMP groups by language label with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val language : kotlin.String = language_example // kotlin.String | language
val label : kotlin.String = label_example // kotlin.String | label
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A vmpgroup document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListVmpGroupDto = apiInstance.findPaginatedVmpGroupsByLabel(language, label, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedVmpGroupsByLabel")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedVmpGroupsByLabel")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **language** | **kotlin.String**| language | [optional]
 **label** | **kotlin.String**| label | [optional]
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A vmpgroup document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListVmpGroupDto**](PaginatedListVmpGroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedVmpGroupsByVmpGroupCode"></a>
# **findPaginatedVmpGroupsByVmpGroupCode**
> PaginatedListVmpGroupDto findPaginatedVmpGroupsByVmpGroupCode(vmpgCode, startKey, startDocumentId, limit)

Finding VMP groups by cmpgCode with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val vmpgCode : kotlin.String = vmpgCode_example // kotlin.String | vmpgCode
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A vmpgroup document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListVmpGroupDto = apiInstance.findPaginatedVmpGroupsByVmpGroupCode(vmpgCode, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedVmpGroupsByVmpGroupCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedVmpGroupsByVmpGroupCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vmpgCode** | **kotlin.String**| vmpgCode |
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A vmpgroup document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListVmpGroupDto**](PaginatedListVmpGroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedVmpsByGroupCode"></a>
# **findPaginatedVmpsByGroupCode**
> PaginatedListVmpDto findPaginatedVmpsByGroupCode(vmpgCode, startKey, startDocumentId, limit)

Finding VMPs by group with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val vmpgCode : kotlin.String = vmpgCode_example // kotlin.String | vmpgCode
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A vmp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListVmpDto = apiInstance.findPaginatedVmpsByGroupCode(vmpgCode, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedVmpsByGroupCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedVmpsByGroupCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vmpgCode** | **kotlin.String**| vmpgCode |
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A vmp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListVmpDto**](PaginatedListVmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedVmpsByGroupId"></a>
# **findPaginatedVmpsByGroupId**
> PaginatedListVmpDto findPaginatedVmpsByGroupId(vmpgId, startKey, startDocumentId, limit)

Finding VMPs by group with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val vmpgId : kotlin.String = vmpgId_example // kotlin.String | vmpgId
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A vmp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListVmpDto = apiInstance.findPaginatedVmpsByGroupId(vmpgId, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedVmpsByGroupId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedVmpsByGroupId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vmpgId** | **kotlin.String**| vmpgId |
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A vmp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListVmpDto**](PaginatedListVmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedVmpsByLabel"></a>
# **findPaginatedVmpsByLabel**
> PaginatedListVmpDto findPaginatedVmpsByLabel(language, label, startKey, startDocumentId, limit)

Finding VMPs by label with pagination.

Returns a paginated list of VMPs by matching label. Matches occur per word

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val language : kotlin.String = language_example // kotlin.String | language
val label : kotlin.String = label_example // kotlin.String | label
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A vmp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListVmpDto = apiInstance.findPaginatedVmpsByLabel(language, label, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedVmpsByLabel")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedVmpsByLabel")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **language** | **kotlin.String**| language | [optional]
 **label** | **kotlin.String**| label | [optional]
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A vmp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListVmpDto**](PaginatedListVmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPaginatedVmpsByVmpCode"></a>
# **findPaginatedVmpsByVmpCode**
> PaginatedListVmpDto findPaginatedVmpsByVmpCode(vmpCode, startKey, startDocumentId, limit)

Finding VMPs by group with pagination.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val vmpCode : kotlin.String = vmpCode_example // kotlin.String | vmpCode
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A vmp document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListVmpDto = apiInstance.findPaginatedVmpsByVmpCode(vmpCode, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findPaginatedVmpsByVmpCode")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findPaginatedVmpsByVmpCode")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **vmpCode** | **kotlin.String**| vmpCode |
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A vmp document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListVmpDto**](PaginatedListVmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findParagraphs"></a>
# **findParagraphs**
> kotlin.collections.List&lt;ParagraphDto&gt; findParagraphs(searchString, language)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val searchString : kotlin.String = searchString_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ParagraphDto> = apiInstance.findParagraphs(searchString, language)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findParagraphs")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findParagraphs")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **searchString** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ParagraphDto&gt;**](ParagraphDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findParagraphsWithCnk"></a>
# **findParagraphsWithCnk**
> kotlin.collections.List&lt;ParagraphDto&gt; findParagraphsWithCnk(cnk, language)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val cnk : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
try {
    val result : kotlin.collections.List<ParagraphDto> = apiInstance.findParagraphsWithCnk(cnk, language)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#findParagraphsWithCnk")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#findParagraphsWithCnk")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cnk** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;ParagraphDto&gt;**](ParagraphDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getAddedDocument"></a>
# **getAddedDocument**
> kotlin.collections.List&lt;InlineResponse200&gt; getAddedDocument(chapterName, paragraphName, verseSeq, docSeq, language, response)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val chapterName : kotlin.String = chapterName_example // kotlin.String | 
val paragraphName : kotlin.String = paragraphName_example // kotlin.String | 
val verseSeq : kotlin.Long = 789 // kotlin.Long | 
val docSeq : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val response : Response =  // Response | 
try {
    val result : kotlin.collections.List<InlineResponse200> = apiInstance.getAddedDocument(chapterName, paragraphName, verseSeq, docSeq, language, response)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#getAddedDocument")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#getAddedDocument")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **chapterName** | **kotlin.String**|  |
 **paragraphName** | **kotlin.String**|  |
 **verseSeq** | **kotlin.Long**|  |
 **docSeq** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **response** | [**Response**](.md)|  |

### Return type

[**kotlin.collections.List&lt;InlineResponse200&gt;**](InlineResponse200.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

<a name="getAmpsForParagraph"></a>
# **getAmpsForParagraph**
> kotlin.collections.List&lt;AmpDto&gt; getAmpsForParagraph(chapterName, paragraphName)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val chapterName : kotlin.String = chapterName_example // kotlin.String | 
val paragraphName : kotlin.String = paragraphName_example // kotlin.String | 
try {
    val result : kotlin.collections.List<AmpDto> = apiInstance.getAmpsForParagraph(chapterName, paragraphName)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#getAmpsForParagraph")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#getAmpsForParagraph")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **chapterName** | **kotlin.String**|  |
 **paragraphName** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;AmpDto&gt;**](AmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getSamVersion"></a>
# **getSamVersion**
> SamVersionDto getSamVersion()

Get Samv2 version.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
try {
    val result : SamVersionDto = apiInstance.getSamVersion()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#getSamVersion")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#getSamVersion")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**SamVersionDto**](SamVersionDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getVersesHierarchy"></a>
# **getVersesHierarchy**
> VerseDto getVersesHierarchy(chapterName, paragraphName)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val chapterName : kotlin.String = chapterName_example // kotlin.String | 
val paragraphName : kotlin.String = paragraphName_example // kotlin.String | 
try {
    val result : VerseDto = apiInstance.getVersesHierarchy(chapterName, paragraphName)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#getVersesHierarchy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#getVersesHierarchy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **chapterName** | **kotlin.String**|  |
 **paragraphName** | **kotlin.String**|  |

### Return type

[**VerseDto**](VerseDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getVtmNamesForParagraph"></a>
# **getVtmNamesForParagraph**
> kotlin.collections.List&lt;kotlin.String&gt; getVtmNamesForParagraph(chapterName, paragraphName, language)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val chapterName : kotlin.String = chapterName_example // kotlin.String | 
val paragraphName : kotlin.String = paragraphName_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.getVtmNamesForParagraph(chapterName, paragraphName, language)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#getVtmNamesForParagraph")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#getVtmNamesForParagraph")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **chapterName** | **kotlin.String**|  |
 **paragraphName** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listAmpsByDmppCodes"></a>
# **listAmpsByDmppCodes**
> kotlin.collections.List&lt;AmpDto&gt; listAmpsByDmppCodes(listOfIdsDto)

Finding AMPs by dmpp code

Returns a list of amps matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<AmpDto> = apiInstance.listAmpsByDmppCodes(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listAmpsByDmppCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listAmpsByDmppCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;AmpDto&gt;**](AmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listAmpsByGroupCodes"></a>
# **listAmpsByGroupCodes**
> kotlin.collections.List&lt;AmpDto&gt; listAmpsByGroupCodes(listOfIdsDto)

Finding AMPs by group.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<AmpDto> = apiInstance.listAmpsByGroupCodes(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listAmpsByGroupCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listAmpsByGroupCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;AmpDto&gt;**](AmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listAmpsByGroupIds"></a>
# **listAmpsByGroupIds**
> kotlin.collections.List&lt;AmpDto&gt; listAmpsByGroupIds(listOfIdsDto)

Finding AMPs by group.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<AmpDto> = apiInstance.listAmpsByGroupIds(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listAmpsByGroupIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listAmpsByGroupIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;AmpDto&gt;**](AmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listAmpsByVmpCodes"></a>
# **listAmpsByVmpCodes**
> kotlin.collections.List&lt;AmpDto&gt; listAmpsByVmpCodes(listOfIdsDto)

Finding AMPs by vmp code.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<AmpDto> = apiInstance.listAmpsByVmpCodes(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listAmpsByVmpCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listAmpsByVmpCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;AmpDto&gt;**](AmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listAmpsByVmpIds"></a>
# **listAmpsByVmpIds**
> kotlin.collections.List&lt;AmpDto&gt; listAmpsByVmpIds(listOfIdsDto)

Finding AMPs by vmp id.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<AmpDto> = apiInstance.listAmpsByVmpIds(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listAmpsByVmpIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listAmpsByVmpIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;AmpDto&gt;**](AmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listNmpsByCnks"></a>
# **listNmpsByCnks**
> kotlin.collections.List&lt;NmpDto&gt; listNmpsByCnks(listOfIdsDto)

Finding NMPs by cnk id.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<NmpDto> = apiInstance.listNmpsByCnks(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listNmpsByCnks")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listNmpsByCnks")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;NmpDto&gt;**](NmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listPharmaceuticalForms"></a>
# **listPharmaceuticalForms**
> kotlin.collections.List&lt;PharmaceuticalFormDto&gt; listPharmaceuticalForms()

List all pharmaceutical forms.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
try {
    val result : kotlin.collections.List<PharmaceuticalFormDto> = apiInstance.listPharmaceuticalForms()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listPharmaceuticalForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listPharmaceuticalForms")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;PharmaceuticalFormDto&gt;**](PharmaceuticalFormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listSubstances"></a>
# **listSubstances**
> kotlin.collections.List&lt;SubstanceDto&gt; listSubstances()

List all substances.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
try {
    val result : kotlin.collections.List<SubstanceDto> = apiInstance.listSubstances()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listSubstances")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listSubstances")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;SubstanceDto&gt;**](SubstanceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listVmpGroupsByVmpGroupCodes"></a>
# **listVmpGroupsByVmpGroupCodes**
> kotlin.collections.List&lt;VmpGroupDto&gt; listVmpGroupsByVmpGroupCodes(listOfIdsDto)

Finding AMPs by group.

Returns a list of group codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<VmpGroupDto> = apiInstance.listVmpGroupsByVmpGroupCodes(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listVmpGroupsByVmpGroupCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listVmpGroupsByVmpGroupCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;VmpGroupDto&gt;**](VmpGroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listVmpsByGroupIds"></a>
# **listVmpsByGroupIds**
> kotlin.collections.List&lt;VmpDto&gt; listVmpsByGroupIds(listOfIdsDto)

Finding VMPs by group.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<VmpDto> = apiInstance.listVmpsByGroupIds(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listVmpsByGroupIds")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listVmpsByGroupIds")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;VmpDto&gt;**](VmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listVmpsByVmpCodes"></a>
# **listVmpsByVmpCodes**
> kotlin.collections.List&lt;VmpDto&gt; listVmpsByVmpCodes(listOfIdsDto)

Finding VMPs by group.

Returns a list of codes matched with given input. If several types are provided, paginantion is not supported

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = Besamv2Api()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<VmpDto> = apiInstance.listVmpsByVmpCodes(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling Besamv2Api#listVmpsByVmpCodes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling Besamv2Api#listVmpsByVmpCodes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;VmpDto&gt;**](VmpDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

