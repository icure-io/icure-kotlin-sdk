# FormApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createForm**](FormApi.md#createForm) | **POST** /rest/v2/form | Create a form with the current user
[**createFormTemplate**](FormApi.md#createFormTemplate) | **POST** /rest/v2/form/template | Create a form template with the current user
[**createForms**](FormApi.md#createForms) | **POST** /rest/v2/form/batch | Create a batch of forms
[**deleteFormTemplate**](FormApi.md#deleteFormTemplate) | **DELETE** /rest/v2/form/template/{formTemplateId} | Delete a form template
[**deleteForms**](FormApi.md#deleteForms) | **POST** /rest/v2/form/delete/batch | Delete forms.
[**getChildrenForms**](FormApi.md#getChildrenForms) | **GET** /rest/v2/form/childrenOf/{formId}/{hcPartyId} | Get a list of forms by parents ids
[**getForm**](FormApi.md#getForm) | **GET** /rest/v2/form/{formId} | Gets a form
[**getFormByLogicalUuid**](FormApi.md#getFormByLogicalUuid) | **GET** /rest/v2/form/logicalUuid/{logicalUuid} | Gets the most recent form with the given logicalUuid
[**getFormByUniqueId**](FormApi.md#getFormByUniqueId) | **GET** /rest/v2/form/uniqueId/{uniqueId} | Gets the most recent form with the given uniqueId
[**getFormTemplate**](FormApi.md#getFormTemplate) | **GET** /rest/v2/form/template/{formTemplateId} | Gets a form template by guid
[**getFormTemplates**](FormApi.md#getFormTemplates) | **GET** /rest/v2/form/template | Gets all form templates for current user
[**getFormTemplatesByGuid**](FormApi.md#getFormTemplatesByGuid) | **GET** /rest/v2/form/template/{specialityCode}/guid/{formTemplateGuid} | Gets a form template
[**getForms**](FormApi.md#getForms) | **POST** /rest/v2/form/byIds | Get a list of forms by ids
[**getFormsByLogicalUuid**](FormApi.md#getFormsByLogicalUuid) | **GET** /rest/v2/form/all/logicalUuid/{logicalUuid} | Gets all forms with given logicalUuid
[**getFormsByUniqueId**](FormApi.md#getFormsByUniqueId) | **GET** /rest/v2/form/all/uniqueId/{uniqueId} | Gets all forms by uniqueId
[**listFormTemplatesBySpeciality**](FormApi.md#listFormTemplatesBySpeciality) | **GET** /rest/v2/form/template/bySpecialty/{specialityCode} | Gets all form templates
[**listFormsByHCPartyAndPatientForeignKeys**](FormApi.md#listFormsByHCPartyAndPatientForeignKeys) | **GET** /rest/v2/form/byHcPartySecretForeignKeys | List forms found By Healthcare Party and secret foreign keys.
[**listFormsDelegationsStubsByHCPartyAndPatientForeignKeys**](FormApi.md#listFormsDelegationsStubsByHCPartyAndPatientForeignKeys) | **GET** /rest/v2/form/byHcPartySecretForeignKeys/delegations | List form stubs found By Healthcare Party and secret foreign keys.
[**modifyForm**](FormApi.md#modifyForm) | **PUT** /rest/v2/form | Modify a form
[**modifyForms**](FormApi.md#modifyForms) | **PUT** /rest/v2/form/batch | Modify a batch of forms
[**newFormDelegations**](FormApi.md#newFormDelegations) | **POST** /rest/v2/form/delegate/{formId} | Delegates a form to a healthcare party
[**setFormsDelegations**](FormApi.md#setFormsDelegations) | **POST** /rest/v2/form/delegations | Update delegations in form.
[**setTemplateAttachmentMulti**](FormApi.md#setTemplateAttachmentMulti) | **PUT** /rest/v2/form/template/{formTemplateId}/attachment/multipart | Update a form template&#39;s layout
[**updateFormTemplate**](FormApi.md#updateFormTemplate) | **PUT** /rest/v2/form/template/{formTemplateId} | Modify a form template with the current user


<a name="createForm"></a>
# **createForm**
> FormDto createForm(formDto)

Create a form with the current user

Returns an instance of created form.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formDto : FormDto =  // FormDto | 
try {
    val result : FormDto = apiInstance.createForm(formDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#createForm")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#createForm")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formDto** | [**FormDto**](FormDto.md)|  |

### Return type

[**FormDto**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createFormTemplate"></a>
# **createFormTemplate**
> FormTemplateDto createFormTemplate(formTemplateDto)

Create a form template with the current user

Returns an instance of created form template.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formTemplateDto : FormTemplateDto =  // FormTemplateDto | 
try {
    val result : FormTemplateDto = apiInstance.createFormTemplate(formTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#createFormTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#createFormTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formTemplateDto** | [**FormTemplateDto**](FormTemplateDto.md)|  |

### Return type

[**FormTemplateDto**](FormTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createForms"></a>
# **createForms**
> kotlin.collections.List&lt;FormDto&gt; createForms(formDto)

Create a batch of forms

Returns the created forms.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formDto : kotlin.collections.List<FormDto> =  // kotlin.collections.List<FormDto> | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.createForms(formDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#createForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#createForms")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formDto** | [**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)|  |

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteFormTemplate"></a>
# **deleteFormTemplate**
> DocIdentifier deleteFormTemplate(formTemplateId)

Delete a form template

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formTemplateId : kotlin.String = formTemplateId_example // kotlin.String | 
try {
    val result : DocIdentifier = apiInstance.deleteFormTemplate(formTemplateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#deleteFormTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#deleteFormTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formTemplateId** | **kotlin.String**|  |

### Return type

[**DocIdentifier**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deleteForms"></a>
# **deleteForms**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteForms(listOfIdsDto)

Delete forms.

Response is a set containing the ID&#39;s of deleted forms.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteForms(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#deleteForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#deleteForms")
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

<a name="getChildrenForms"></a>
# **getChildrenForms**
> kotlin.collections.List&lt;FormDto&gt; getChildrenForms(formId, hcPartyId)

Get a list of forms by parents ids

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formId : kotlin.String = formId_example // kotlin.String | 
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.getChildrenForms(formId, hcPartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getChildrenForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getChildrenForms")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formId** | **kotlin.String**|  |
 **hcPartyId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getForm"></a>
# **getForm**
> FormDto getForm(formId)

Gets a form

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formId : kotlin.String = formId_example // kotlin.String | 
try {
    val result : FormDto = apiInstance.getForm(formId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getForm")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getForm")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formId** | **kotlin.String**|  |

### Return type

[**FormDto**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFormByLogicalUuid"></a>
# **getFormByLogicalUuid**
> FormDto getFormByLogicalUuid(logicalUuid)

Gets the most recent form with the given logicalUuid

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val logicalUuid : kotlin.String = logicalUuid_example // kotlin.String | 
try {
    val result : FormDto = apiInstance.getFormByLogicalUuid(logicalUuid)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getFormByLogicalUuid")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getFormByLogicalUuid")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **logicalUuid** | **kotlin.String**|  |

### Return type

[**FormDto**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFormByUniqueId"></a>
# **getFormByUniqueId**
> FormDto getFormByUniqueId(uniqueId)

Gets the most recent form with the given uniqueId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val uniqueId : kotlin.String = uniqueId_example // kotlin.String | 
try {
    val result : FormDto = apiInstance.getFormByUniqueId(uniqueId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getFormByUniqueId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getFormByUniqueId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **uniqueId** | **kotlin.String**|  |

### Return type

[**FormDto**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFormTemplate"></a>
# **getFormTemplate**
> FormTemplateDto getFormTemplate(formTemplateId)

Gets a form template by guid

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formTemplateId : kotlin.String = formTemplateId_example // kotlin.String | 
try {
    val result : FormTemplateDto = apiInstance.getFormTemplate(formTemplateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getFormTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getFormTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formTemplateId** | **kotlin.String**|  |

### Return type

[**FormTemplateDto**](FormTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFormTemplates"></a>
# **getFormTemplates**
> kotlin.collections.List&lt;FormTemplateDto&gt; getFormTemplates(loadLayout)

Gets all form templates for current user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val loadLayout : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<FormTemplateDto> = apiInstance.getFormTemplates(loadLayout)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getFormTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getFormTemplates")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **loadLayout** | **kotlin.Boolean**|  | [optional]

### Return type

[**kotlin.collections.List&lt;FormTemplateDto&gt;**](FormTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFormTemplatesByGuid"></a>
# **getFormTemplatesByGuid**
> kotlin.collections.List&lt;FormTemplateDto&gt; getFormTemplatesByGuid(formTemplateGuid, specialityCode)

Gets a form template

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formTemplateGuid : kotlin.String = formTemplateGuid_example // kotlin.String | 
val specialityCode : kotlin.String = specialityCode_example // kotlin.String | 
try {
    val result : kotlin.collections.List<FormTemplateDto> = apiInstance.getFormTemplatesByGuid(formTemplateGuid, specialityCode)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getFormTemplatesByGuid")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getFormTemplatesByGuid")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formTemplateGuid** | **kotlin.String**|  |
 **specialityCode** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;FormTemplateDto&gt;**](FormTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getForms"></a>
# **getForms**
> kotlin.collections.List&lt;FormDto&gt; getForms(listOfIdsDto)

Get a list of forms by ids

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.getForms(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getForms")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getFormsByLogicalUuid"></a>
# **getFormsByLogicalUuid**
> kotlin.collections.List&lt;FormDto&gt; getFormsByLogicalUuid(logicalUuid)

Gets all forms with given logicalUuid

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val logicalUuid : kotlin.String = logicalUuid_example // kotlin.String | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.getFormsByLogicalUuid(logicalUuid)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getFormsByLogicalUuid")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getFormsByLogicalUuid")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **logicalUuid** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getFormsByUniqueId"></a>
# **getFormsByUniqueId**
> kotlin.collections.List&lt;FormDto&gt; getFormsByUniqueId(uniqueId)

Gets all forms by uniqueId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val uniqueId : kotlin.String = uniqueId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.getFormsByUniqueId(uniqueId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#getFormsByUniqueId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#getFormsByUniqueId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **uniqueId** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listFormTemplatesBySpeciality"></a>
# **listFormTemplatesBySpeciality**
> kotlin.collections.List&lt;FormTemplateDto&gt; listFormTemplatesBySpeciality(specialityCode, loadLayout)

Gets all form templates

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val specialityCode : kotlin.String = specialityCode_example // kotlin.String | 
val loadLayout : kotlin.Boolean = true // kotlin.Boolean | 
try {
    val result : kotlin.collections.List<FormTemplateDto> = apiInstance.listFormTemplatesBySpeciality(specialityCode, loadLayout)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#listFormTemplatesBySpeciality")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#listFormTemplatesBySpeciality")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **specialityCode** | **kotlin.String**|  |
 **loadLayout** | **kotlin.Boolean**|  | [optional]

### Return type

[**kotlin.collections.List&lt;FormTemplateDto&gt;**](FormTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listFormsByHCPartyAndPatientForeignKeys"></a>
# **listFormsByHCPartyAndPatientForeignKeys**
> kotlin.collections.List&lt;FormDto&gt; listFormsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys, healthElementId, planOfActionId, formTemplateId)

List forms found By Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
val healthElementId : kotlin.String = healthElementId_example // kotlin.String | 
val planOfActionId : kotlin.String = planOfActionId_example // kotlin.String | 
val formTemplateId : kotlin.String = formTemplateId_example // kotlin.String | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.listFormsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys, healthElementId, planOfActionId, formTemplateId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#listFormsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#listFormsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **secretFKeys** | **kotlin.String**|  |
 **healthElementId** | **kotlin.String**|  | [optional]
 **planOfActionId** | **kotlin.String**|  | [optional]
 **formTemplateId** | **kotlin.String**|  | [optional]

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listFormsDelegationsStubsByHCPartyAndPatientForeignKeys"></a>
# **listFormsDelegationsStubsByHCPartyAndPatientForeignKeys**
> kotlin.collections.List&lt;IcureStubDto&gt; listFormsDelegationsStubsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)

List form stubs found By Healthcare Party and secret foreign keys.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val secretFKeys : kotlin.String = secretFKeys_example // kotlin.String | 
try {
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.listFormsDelegationsStubsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#listFormsDelegationsStubsByHCPartyAndPatientForeignKeys")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#listFormsDelegationsStubsByHCPartyAndPatientForeignKeys")
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

<a name="modifyForm"></a>
# **modifyForm**
> FormDto modifyForm(formDto)

Modify a form

Returns the modified form.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formDto : FormDto =  // FormDto | 
try {
    val result : FormDto = apiInstance.modifyForm(formDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#modifyForm")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#modifyForm")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formDto** | [**FormDto**](FormDto.md)|  |

### Return type

[**FormDto**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyForms"></a>
# **modifyForms**
> kotlin.collections.List&lt;FormDto&gt; modifyForms(formDto)

Modify a batch of forms

Returns the modified forms.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formDto : kotlin.collections.List<FormDto> =  // kotlin.collections.List<FormDto> | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.modifyForms(formDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#modifyForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#modifyForms")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formDto** | [**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)|  |

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="newFormDelegations"></a>
# **newFormDelegations**
> FormDto newFormDelegations(formId, delegationDto)

Delegates a form to a healthcare party

It delegates a form to a healthcare party. Returns the form with the new delegations.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formId : kotlin.String = formId_example // kotlin.String | 
val delegationDto : kotlin.collections.List<DelegationDto> =  // kotlin.collections.List<DelegationDto> | 
try {
    val result : FormDto = apiInstance.newFormDelegations(formId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#newFormDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#newFormDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formId** | **kotlin.String**|  |
 **delegationDto** | [**kotlin.collections.List&lt;DelegationDto&gt;**](DelegationDto.md)|  |

### Return type

[**FormDto**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setFormsDelegations"></a>
# **setFormsDelegations**
> kotlin.collections.List&lt;IcureStubDto&gt; setFormsDelegations(icureStubDto)

Update delegations in form.

Keys must be delimited by coma

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val icureStubDto : kotlin.collections.List<IcureStubDto> =  // kotlin.collections.List<IcureStubDto> | 
try {
    val result : kotlin.collections.List<IcureStubDto> = apiInstance.setFormsDelegations(icureStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#setFormsDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#setFormsDelegations")
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

<a name="setTemplateAttachmentMulti"></a>
# **setTemplateAttachmentMulti**
> kotlin.String setTemplateAttachmentMulti(formTemplateId, attachment)

Update a form template&#39;s layout

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formTemplateId : kotlin.String = formTemplateId_example // kotlin.String | 
val attachment : kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> = BYTE_ARRAY_DATA_HERE // kotlin.collections.List<io.icure.kraken.client.infrastructure.ByteArrayWrapper> | 
try {
    val result : kotlin.String = apiInstance.setTemplateAttachmentMulti(formTemplateId, attachment)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#setTemplateAttachmentMulti")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#setTemplateAttachmentMulti")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formTemplateId** | **kotlin.String**|  |
 **attachment** | [**kotlin.collections.List&lt;io.icure.kraken.client.infrastructure.ByteArrayWrapper&gt;**](io.icure.kraken.client.infrastructure.ByteArrayWrapper.md)|  |

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: multipart/form-data
 - **Accept**: */*

<a name="updateFormTemplate"></a>
# **updateFormTemplate**
> FormTemplateDto updateFormTemplate(formTemplateId, formTemplateDto)

Modify a form template with the current user

Returns an instance of created form template.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = FormApi()
val formTemplateId : kotlin.String = formTemplateId_example // kotlin.String | 
val formTemplateDto : FormTemplateDto =  // FormTemplateDto | 
try {
    val result : FormTemplateDto = apiInstance.updateFormTemplate(formTemplateId, formTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling FormApi#updateFormTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling FormApi#updateFormTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **formTemplateId** | **kotlin.String**|  |
 **formTemplateDto** | [**FormTemplateDto**](FormTemplateDto.md)|  |

### Return type

[**FormTemplateDto**](FormTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

