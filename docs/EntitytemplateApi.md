# EntityTemplateApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createEntityTemplate**](EntityTemplateApi.md#createEntityTemplate) | **POST** /rest/v2/entitytemplate | Create a EntityTemplate
[**createEntityTemplates**](EntityTemplateApi.md#createEntityTemplates) | **POST** /rest/v2/entitytemplate/batch | Create a batch of entityTemplates
[**deleteEntityTemplate**](EntityTemplateApi.md#deleteEntityTemplate) | **POST** /rest/v2/entitytemplate/delete/batch | Delete entity templates
[**findAllEntityTemplatesByKeyword**](EntityTemplateApi.md#findAllEntityTemplatesByKeyword) | **GET** /rest/v2/entitytemplate/findAll/{type}/keyword/{keyword} | Finding entityTemplates by entityTemplate, type and version with pagination.
[**getEntityTemplate**](EntityTemplateApi.md#getEntityTemplate) | **GET** /rest/v2/entitytemplate/{entityTemplateId} | Get a entityTemplate
[**getEntityTemplates**](EntityTemplateApi.md#getEntityTemplates) | **POST** /rest/v2/entitytemplate/byIds | Get a list of entityTemplates by ids
[**listAllEntityTemplatesBy**](EntityTemplateApi.md#listAllEntityTemplatesBy) | **GET** /rest/v2/entitytemplate/findAll/{type} | Finding entityTemplates by entityTemplate, type and version with pagination.
[**listEntityTemplatesBy**](EntityTemplateApi.md#listEntityTemplatesBy) | **GET** /rest/v2/entitytemplate/find/{userId}/{type} | Finding entityTemplates by userId, entityTemplate, type and version with pagination.
[**listEntityTemplatesByKeyword**](EntityTemplateApi.md#listEntityTemplatesByKeyword) | **GET** /rest/v2/entitytemplate/find/{userId}/{type}/keyword/{keyword} | Finding entityTemplates by userId, type and keyword.
[**modifyEntityTemplate**](EntityTemplateApi.md#modifyEntityTemplate) | **PUT** /rest/v2/entitytemplate | Modify a entityTemplate
[**modifyEntityTemplates**](EntityTemplateApi.md#modifyEntityTemplates) | **PUT** /rest/v2/entitytemplate/batch | Modify a batch of entityTemplates


<a name="createEntityTemplate"></a>
# **createEntityTemplate**
> EntityTemplateDto createEntityTemplate(entityTemplateDto)

Create a EntityTemplate

Type, EntityTemplate and Version are required.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val entityTemplateDto : EntityTemplateDto =  // EntityTemplateDto | 
try {
    val result : EntityTemplateDto = apiInstance.createEntityTemplate(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#createEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#createEntityTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityTemplateDto** | [**EntityTemplateDto**](EntityTemplateDto.md)|  |

### Return type

[**EntityTemplateDto**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createEntityTemplates"></a>
# **createEntityTemplates**
> kotlin.collections.List&lt;EntityTemplateDto&gt; createEntityTemplates(entityTemplateDto)

Create a batch of entityTemplates

Returns the modified entityTemplates.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val entityTemplateDto : kotlin.collections.List<EntityTemplateDto> =  // kotlin.collections.List<EntityTemplateDto> | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.createEntityTemplates(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#createEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#createEntityTemplates")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityTemplateDto** | [**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)|  |

### Return type

[**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteEntityTemplate"></a>
# **deleteEntityTemplate**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteEntityTemplate(listOfIdsDto)

Delete entity templates

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteEntityTemplate(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#deleteEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#deleteEntityTemplate")
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

<a name="findAllEntityTemplatesByKeyword"></a>
# **findAllEntityTemplatesByKeyword**
> kotlin.collections.List&lt;EntityTemplateDto&gt; findAllEntityTemplatesByKeyword(type, keyword, includeEntities)

Finding entityTemplates by entityTemplate, type and version with pagination.

Returns a list of entityTemplates matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val type : kotlin.String = type_example // kotlin.String | 
val keyword : kotlin.String = keyword_example // kotlin.String | 
val includeEntities : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.findAllEntityTemplatesByKeyword(type, keyword, includeEntities)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#findAllEntityTemplatesByKeyword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#findAllEntityTemplatesByKeyword")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **type** | **kotlin.String**|  |
 **keyword** | **kotlin.String**|  |
 **includeEntities** | **kotlin.Boolean**|  | [optional]

### Return type

[**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getEntityTemplate"></a>
# **getEntityTemplate**
> EntityTemplateDto getEntityTemplate(entityTemplateId)

Get a entityTemplate

Get a entityTemplate based on ID or (entityTemplate,type,version) as query strings. (entityTemplate,type,version) is unique.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val entityTemplateId : kotlin.String = entityTemplateId_example // kotlin.String | EntityTemplate id
try {
    val result : EntityTemplateDto = apiInstance.getEntityTemplate(entityTemplateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#getEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#getEntityTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityTemplateId** | **kotlin.String**| EntityTemplate id |

### Return type

[**EntityTemplateDto**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getEntityTemplates"></a>
# **getEntityTemplates**
> kotlin.collections.List&lt;EntityTemplateDto&gt; getEntityTemplates(listOfIdsDto)

Get a list of entityTemplates by ids

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.getEntityTemplates(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#getEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#getEntityTemplates")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listAllEntityTemplatesBy"></a>
# **listAllEntityTemplatesBy**
> kotlin.collections.List&lt;EntityTemplateDto&gt; listAllEntityTemplatesBy(type, searchString, includeEntities)

Finding entityTemplates by entityTemplate, type and version with pagination.

Returns a list of entityTemplates matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val type : kotlin.String = type_example // kotlin.String | 
val searchString : kotlin.String = searchString_example // kotlin.String | 
val includeEntities : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.listAllEntityTemplatesBy(type, searchString, includeEntities)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#listAllEntityTemplatesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#listAllEntityTemplatesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **type** | **kotlin.String**|  |
 **searchString** | **kotlin.String**|  | [optional]
 **includeEntities** | **kotlin.Boolean**|  | [optional]

### Return type

[**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listEntityTemplatesBy"></a>
# **listEntityTemplatesBy**
> kotlin.collections.List&lt;EntityTemplateDto&gt; listEntityTemplatesBy(userId, type, searchString, includeEntities)

Finding entityTemplates by userId, entityTemplate, type and version with pagination.

Returns a list of entityTemplates matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val type : kotlin.String = type_example // kotlin.String | 
val searchString : kotlin.String = searchString_example // kotlin.String | 
val includeEntities : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.listEntityTemplatesBy(userId, type, searchString, includeEntities)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#listEntityTemplatesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#listEntityTemplatesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **type** | **kotlin.String**|  |
 **searchString** | **kotlin.String**|  | [optional]
 **includeEntities** | **kotlin.Boolean**|  | [optional]

### Return type

[**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listEntityTemplatesByKeyword"></a>
# **listEntityTemplatesByKeyword**
> kotlin.collections.List&lt;EntityTemplateDto&gt; listEntityTemplatesByKeyword(userId, type, keyword, includeEntities)

Finding entityTemplates by userId, type and keyword.

Returns a list of entityTemplates matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val type : kotlin.String = type_example // kotlin.String | 
val keyword : kotlin.String = keyword_example // kotlin.String | 
val includeEntities : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.listEntityTemplatesByKeyword(userId, type, keyword, includeEntities)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#listEntityTemplatesByKeyword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#listEntityTemplatesByKeyword")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **type** | **kotlin.String**|  |
 **keyword** | **kotlin.String**|  |
 **includeEntities** | **kotlin.Boolean**|  | [optional]

### Return type

[**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyEntityTemplate"></a>
# **modifyEntityTemplate**
> EntityTemplateDto modifyEntityTemplate(entityTemplateDto)

Modify a entityTemplate

Modification of (type, entityTemplate, version) is not allowed.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val entityTemplateDto : EntityTemplateDto =  // EntityTemplateDto | 
try {
    val result : EntityTemplateDto = apiInstance.modifyEntityTemplate(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#modifyEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#modifyEntityTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityTemplateDto** | [**EntityTemplateDto**](EntityTemplateDto.md)|  |

### Return type

[**EntityTemplateDto**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyEntityTemplates"></a>
# **modifyEntityTemplates**
> kotlin.collections.List&lt;EntityTemplateDto&gt; modifyEntityTemplates(entityTemplateDto)

Modify a batch of entityTemplates

Returns the modified entityTemplates.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntityTemplateApi()
val entityTemplateDto : kotlin.collections.List<EntityTemplateDto> =  // kotlin.collections.List<EntityTemplateDto> | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.modifyEntityTemplates(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntityTemplateApi#modifyEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntityTemplateApi#modifyEntityTemplates")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityTemplateDto** | [**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)|  |

### Return type

[**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

