# EntitytemplateApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createEntityTemplate**](EntitytemplateApi.md#createEntityTemplate) | **POST** /rest/v1/entitytemplate | Create a EntityTemplate
[**createEntityTemplates**](EntitytemplateApi.md#createEntityTemplates) | **POST** /rest/v1/entitytemplate/batch | Create a batch of entityTemplates
[**deleteEntityTemplate**](EntitytemplateApi.md#deleteEntityTemplate) | **DELETE** /rest/v1/entitytemplate/{entityTemplateIds} | Delete entity templates
[**findAllEntityTemplates**](EntitytemplateApi.md#findAllEntityTemplates) | **GET** /rest/v1/entitytemplate/findAll/{type} | Finding entityTemplates by entityTemplate, type and version with pagination.
[**findAllEntityTemplatesByKeyword**](EntitytemplateApi.md#findAllEntityTemplatesByKeyword) | **GET** /rest/v1/entitytemplate/findAll/{type}/keyword/{keyword} | Finding entityTemplates by entityTemplate, type and version with pagination.
[**findEntityTemplates**](EntitytemplateApi.md#findEntityTemplates) | **GET** /rest/v1/entitytemplate/find/{userId}/{type} | Finding entityTemplates by userId, entityTemplate, type and version with pagination.
[**findEntityTemplatesByKeyword**](EntitytemplateApi.md#findEntityTemplatesByKeyword) | **GET** /rest/v1/entitytemplate/find/{userId}/{type}/keyword/{keyword} | Finding entityTemplates by userId, type and keyword.
[**getEntityTemplate**](EntitytemplateApi.md#getEntityTemplate) | **GET** /rest/v1/entitytemplate/{entityTemplateId} | Get a entityTemplate
[**getEntityTemplates**](EntitytemplateApi.md#getEntityTemplates) | **GET** /rest/v1/entitytemplate/byIds/{entityTemplateIds} | Get a list of entityTemplates by ids
[**modifyEntityTemplate**](EntitytemplateApi.md#modifyEntityTemplate) | **PUT** /rest/v1/entitytemplate | Modify a entityTemplate
[**modifyEntityTemplates**](EntitytemplateApi.md#modifyEntityTemplates) | **PUT** /rest/v1/entitytemplate/batch | Modify a batch of entityTemplates


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

val apiInstance = EntitytemplateApi()
val entityTemplateDto : EntityTemplateDto =  // EntityTemplateDto | 
try {
    val result : EntityTemplateDto = apiInstance.createEntityTemplate(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#createEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#createEntityTemplate")
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

val apiInstance = EntitytemplateApi()
val entityTemplateDto : kotlin.collections.List<EntityTemplateDto> =  // kotlin.collections.List<EntityTemplateDto> | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.createEntityTemplates(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#createEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#createEntityTemplates")
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
> kotlin.collections.List&lt;DocIdentifier&gt; deleteEntityTemplate(entityTemplateIds)

Delete entity templates

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntitytemplateApi()
val entityTemplateIds : kotlin.String = entityTemplateIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteEntityTemplate(entityTemplateIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#deleteEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#deleteEntityTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityTemplateIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findAllEntityTemplates"></a>
# **findAllEntityTemplates**
> kotlin.collections.List&lt;EntityTemplateDto&gt; findAllEntityTemplates(type, searchString, includeEntities)

Finding entityTemplates by entityTemplate, type and version with pagination.

Returns a list of entityTemplates matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntitytemplateApi()
val type : kotlin.String = type_example // kotlin.String | 
val searchString : kotlin.String = searchString_example // kotlin.String | 
val includeEntities : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.findAllEntityTemplates(type, searchString, includeEntities)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#findAllEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#findAllEntityTemplates")
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

val apiInstance = EntitytemplateApi()
val type : kotlin.String = type_example // kotlin.String | 
val keyword : kotlin.String = keyword_example // kotlin.String | 
val includeEntities : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.findAllEntityTemplatesByKeyword(type, keyword, includeEntities)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#findAllEntityTemplatesByKeyword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#findAllEntityTemplatesByKeyword")
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

<a name="findEntityTemplates"></a>
# **findEntityTemplates**
> kotlin.collections.List&lt;EntityTemplateDto&gt; findEntityTemplates(userId, type, searchString, includeEntities)

Finding entityTemplates by userId, entityTemplate, type and version with pagination.

Returns a list of entityTemplates matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntitytemplateApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val type : kotlin.String = type_example // kotlin.String | 
val searchString : kotlin.String = searchString_example // kotlin.String | 
val includeEntities : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.findEntityTemplates(userId, type, searchString, includeEntities)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#findEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#findEntityTemplates")
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

<a name="findEntityTemplatesByKeyword"></a>
# **findEntityTemplatesByKeyword**
> kotlin.collections.List&lt;EntityTemplateDto&gt; findEntityTemplatesByKeyword(userId, type, keyword, includeEntities)

Finding entityTemplates by userId, type and keyword.

Returns a list of entityTemplates matched with given input.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntitytemplateApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val type : kotlin.String = type_example // kotlin.String | 
val keyword : kotlin.String = keyword_example // kotlin.String | 
val includeEntities : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.findEntityTemplatesByKeyword(userId, type, keyword, includeEntities)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#findEntityTemplatesByKeyword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#findEntityTemplatesByKeyword")
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

val apiInstance = EntitytemplateApi()
val entityTemplateId : kotlin.String = entityTemplateId_example // kotlin.String | EntityTemplate id
try {
    val result : EntityTemplateDto = apiInstance.getEntityTemplate(entityTemplateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#getEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#getEntityTemplate")
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
> kotlin.collections.List&lt;EntityTemplateDto&gt; getEntityTemplates(entityTemplateIds)

Get a list of entityTemplates by ids

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = EntitytemplateApi()
val entityTemplateIds : kotlin.String = entityTemplateIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.getEntityTemplates(entityTemplateIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#getEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#getEntityTemplates")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **entityTemplateIds** | **kotlin.String**|  |

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

val apiInstance = EntitytemplateApi()
val entityTemplateDto : EntityTemplateDto =  // EntityTemplateDto | 
try {
    val result : EntityTemplateDto = apiInstance.modifyEntityTemplate(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#modifyEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#modifyEntityTemplate")
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

val apiInstance = EntitytemplateApi()
val entityTemplateDto : kotlin.collections.List<EntityTemplateDto> =  // kotlin.collections.List<EntityTemplateDto> | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.modifyEntityTemplates(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling EntitytemplateApi#modifyEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling EntitytemplateApi#modifyEntityTemplates")
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

