# TmpApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createTmpClassification**](TmpApi.md#createTmpClassification) | **POST** /rest/v1/tmp/classification | Create a classification with the current user
[**createTmpClassifications**](TmpApi.md#createTmpClassifications) | **POST** /rest/v1/tmp/classification/batch | Create a classification with the current user
[**createTmpContact**](TmpApi.md#createTmpContact) | **POST** /rest/v1/tmp/contact | Create a contact with the current user
[**createTmpContacts**](TmpApi.md#createTmpContacts) | **POST** /rest/v1/tmp/contact/batch | Create a contact with the current user
[**createTmpDatabase**](TmpApi.md#createTmpDatabase) | **POST** /rest/v1/tmp | Create tmp database for current user
[**createTmpDocument**](TmpApi.md#createTmpDocument) | **POST** /rest/v1/tmp/document | Create a document with the current user
[**createTmpDocuments**](TmpApi.md#createTmpDocuments) | **POST** /rest/v1/tmp/document/batch | Create a document with the current user
[**createTmpEntityTemplate**](TmpApi.md#createTmpEntityTemplate) | **POST** /rest/v1/tmp/entityTemplate | Create a entityTemplate with the current user
[**createTmpEntityTemplates**](TmpApi.md#createTmpEntityTemplates) | **POST** /rest/v1/tmp/entityTemplate/batch | Create a entityTemplate with the current user
[**createTmpForm**](TmpApi.md#createTmpForm) | **POST** /rest/v1/tmp/form | Create a form with the current user
[**createTmpForms**](TmpApi.md#createTmpForms) | **POST** /rest/v1/tmp/form/batch | Create a form with the current user
[**createTmpHealthElement**](TmpApi.md#createTmpHealthElement) | **POST** /rest/v1/tmp/healthElement | Create a healthElement with the current user
[**createTmpHealthElements**](TmpApi.md#createTmpHealthElements) | **POST** /rest/v1/tmp/healthElement/batch | Create a healthElement with the current user
[**createTmpInvoice**](TmpApi.md#createTmpInvoice) | **POST** /rest/v1/tmp/invoice | Create a invoice with the current user
[**createTmpInvoices**](TmpApi.md#createTmpInvoices) | **POST** /rest/v1/tmp/invoice/batch | Create a invoice with the current user
[**createTmpMessage**](TmpApi.md#createTmpMessage) | **POST** /rest/v1/tmp/message | Create a message with the current user
[**createTmpMessages**](TmpApi.md#createTmpMessages) | **POST** /rest/v1/tmp/message/batch | Create a message with the current user
[**createTmpPatient**](TmpApi.md#createTmpPatient) | **POST** /rest/v1/tmp/patient | Create a patient with the current user
[**createTmpPatients**](TmpApi.md#createTmpPatients) | **POST** /rest/v1/tmp/patient/batch | Create a patient with the current user
[**deleteTmpItems**](TmpApi.md#deleteTmpItems) | **POST** /rest/v1/tmp/batch/delete | Soft delete items.
[**destroyTmpDatabase**](TmpApi.md#destroyTmpDatabase) | **DELETE** /rest/v1/tmp | Destroy tmp database for current user
[**getTmpClassification**](TmpApi.md#getTmpClassification) | **GET** /rest/v1/tmp/classification/byId/{id} | Get a classification by id
[**getTmpClassifications**](TmpApi.md#getTmpClassifications) | **POST** /rest/v1/tmp/classification/get | Get classifications by ids with the current user
[**getTmpContact**](TmpApi.md#getTmpContact) | **GET** /rest/v1/tmp/contact/byId/{id} | Get a contact by id
[**getTmpContacts**](TmpApi.md#getTmpContacts) | **POST** /rest/v1/tmp/contact/get | Get contacts by ids with the current user
[**getTmpDocument**](TmpApi.md#getTmpDocument) | **GET** /rest/v1/tmp/document/byId/{id} | Get a document by id
[**getTmpDocuments**](TmpApi.md#getTmpDocuments) | **POST** /rest/v1/tmp/document/get | Get documents by ids with the current user
[**getTmpEntityTemplate**](TmpApi.md#getTmpEntityTemplate) | **GET** /rest/v1/tmp/entityTemplate/byId/{id} | Get a entityTemplate by id
[**getTmpEntityTemplates**](TmpApi.md#getTmpEntityTemplates) | **POST** /rest/v1/tmp/entityTemplate/get | Get entityTemplates by ids with the current user
[**getTmpForm**](TmpApi.md#getTmpForm) | **GET** /rest/v1/tmp/form/byId/{id} | Get a form by id
[**getTmpForms**](TmpApi.md#getTmpForms) | **POST** /rest/v1/tmp/form/get | Get forms by ids with the current user
[**getTmpHealthElement**](TmpApi.md#getTmpHealthElement) | **GET** /rest/v1/tmp/healthElement/byId/{id} | Get a healthElement by id
[**getTmpHealthElements**](TmpApi.md#getTmpHealthElements) | **POST** /rest/v1/tmp/healthElement/get | Get healthElements by ids with the current user
[**getTmpInvoice**](TmpApi.md#getTmpInvoice) | **GET** /rest/v1/tmp/invoice/byId/{id} | Get a invoice by id
[**getTmpInvoices**](TmpApi.md#getTmpInvoices) | **POST** /rest/v1/tmp/invoice/get | Get invoices by ids with the current user
[**getTmpMessage**](TmpApi.md#getTmpMessage) | **GET** /rest/v1/tmp/message/byId/{id} | Get a message by id
[**getTmpMessages**](TmpApi.md#getTmpMessages) | **POST** /rest/v1/tmp/message/get | Get messages by ids with the current user
[**getTmpPatient**](TmpApi.md#getTmpPatient) | **GET** /rest/v1/tmp/patient/byId/{id} | Get a patient by id
[**getTmpPatients**](TmpApi.md#getTmpPatients) | **POST** /rest/v1/tmp/patient/get | Get patients by ids with the current user
[**listTmpClassifications**](TmpApi.md#listTmpClassifications) | **GET** /rest/v1/tmp/classification/list | List classifications with the current user
[**listTmpContacts**](TmpApi.md#listTmpContacts) | **GET** /rest/v1/tmp/contact/list | List contacts with the current user
[**listTmpDocuments**](TmpApi.md#listTmpDocuments) | **GET** /rest/v1/tmp/document/list | List documents with the current user
[**listTmpEntityTemplates**](TmpApi.md#listTmpEntityTemplates) | **GET** /rest/v1/tmp/entityTemplate/list | List entityTemplates with the current user
[**listTmpForms**](TmpApi.md#listTmpForms) | **GET** /rest/v1/tmp/form/list | List forms with the current user
[**listTmpHealthElements**](TmpApi.md#listTmpHealthElements) | **GET** /rest/v1/tmp/healthElement/list | List healthElements with the current user
[**listTmpInvoices**](TmpApi.md#listTmpInvoices) | **GET** /rest/v1/tmp/invoice/list | List invoices with the current user
[**listTmpMessages**](TmpApi.md#listTmpMessages) | **GET** /rest/v1/tmp/message/list | List messages with the current user
[**listTmpPatients**](TmpApi.md#listTmpPatients) | **GET** /rest/v1/tmp/patient/list | List patients with the current user
[**modifyTmpClassification**](TmpApi.md#modifyTmpClassification) | **PUT** /rest/v1/tmp/classification | Modify a classification
[**modifyTmpClassifications**](TmpApi.md#modifyTmpClassifications) | **PUT** /rest/v1/tmp/classification/batch | Modify a batch of healthcare elements
[**modifyTmpContact**](TmpApi.md#modifyTmpContact) | **PUT** /rest/v1/tmp/contact | Modify a contact
[**modifyTmpContacts**](TmpApi.md#modifyTmpContacts) | **PUT** /rest/v1/tmp/contact/batch | Modify a batch of healthcare elements
[**modifyTmpDocument**](TmpApi.md#modifyTmpDocument) | **PUT** /rest/v1/tmp/document | Modify a document
[**modifyTmpDocuments**](TmpApi.md#modifyTmpDocuments) | **PUT** /rest/v1/tmp/document/batch | Modify a batch of healthcare elements
[**modifyTmpEntityTemplate**](TmpApi.md#modifyTmpEntityTemplate) | **PUT** /rest/v1/tmp/entityTemplate | Modify a entityTemplate
[**modifyTmpEntityTemplates**](TmpApi.md#modifyTmpEntityTemplates) | **PUT** /rest/v1/tmp/entityTemplate/batch | Modify a batch of healthcare elements
[**modifyTmpForm**](TmpApi.md#modifyTmpForm) | **PUT** /rest/v1/tmp/form | Modify a form
[**modifyTmpForms**](TmpApi.md#modifyTmpForms) | **PUT** /rest/v1/tmp/form/batch | Modify a batch of healthcare elements
[**modifyTmpHealthElement**](TmpApi.md#modifyTmpHealthElement) | **PUT** /rest/v1/tmp/healthElement | Modify a healthElement
[**modifyTmpHealthElements**](TmpApi.md#modifyTmpHealthElements) | **PUT** /rest/v1/tmp/healthElement/batch | Modify a batch of healthcare elements
[**modifyTmpInvoice**](TmpApi.md#modifyTmpInvoice) | **PUT** /rest/v1/tmp/invoice | Modify a invoice
[**modifyTmpInvoices**](TmpApi.md#modifyTmpInvoices) | **PUT** /rest/v1/tmp/invoice/batch | Modify a batch of healthcare elements
[**modifyTmpMessage**](TmpApi.md#modifyTmpMessage) | **PUT** /rest/v1/tmp/message | Modify a message
[**modifyTmpMessages**](TmpApi.md#modifyTmpMessages) | **PUT** /rest/v1/tmp/message/batch | Modify a batch of healthcare elements
[**modifyTmpPatient**](TmpApi.md#modifyTmpPatient) | **PUT** /rest/v1/tmp/patient | Modify a patient
[**modifyTmpPatients**](TmpApi.md#modifyTmpPatients) | **PUT** /rest/v1/tmp/patient/batch | Modify a batch of healthcare elements
[**purgeTmpItems**](TmpApi.md#purgeTmpItems) | **POST** /rest/v1/tmp/batch/purge | Hard delete items.
[**replicateToTmpDatabase**](TmpApi.md#replicateToTmpDatabase) | **POST** /rest/v1/tmp/replicate/from/{from} | 


<a name="createTmpClassification"></a>
# **createTmpClassification**
> ClassificationDto createTmpClassification(classificationDto)

Create a classification with the current user

Returns an instance of created classification.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val classificationDto : ClassificationDto =  // ClassificationDto | 
try {
    val result : ClassificationDto = apiInstance.createTmpClassification(classificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpClassification")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpClassification")
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

<a name="createTmpClassifications"></a>
# **createTmpClassifications**
> kotlin.collections.List&lt;ClassificationDto&gt; createTmpClassifications(classificationDto)

Create a classification with the current user

Returns an instance of created classification.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val classificationDto : kotlin.collections.List<ClassificationDto> =  // kotlin.collections.List<ClassificationDto> | 
try {
    val result : kotlin.collections.List<ClassificationDto> = apiInstance.createTmpClassifications(classificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpClassifications")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpClassifications")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationDto** | [**kotlin.collections.List&lt;ClassificationDto&gt;**](ClassificationDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ClassificationDto&gt;**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpContact"></a>
# **createTmpContact**
> ContactDto createTmpContact(contactDto)

Create a contact with the current user

Returns an instance of created contact.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val contactDto : ContactDto =  // ContactDto | 
try {
    val result : ContactDto = apiInstance.createTmpContact(contactDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpContact")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpContact")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactDto** | [**ContactDto**](ContactDto.md)|  |

### Return type

[**ContactDto**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpContacts"></a>
# **createTmpContacts**
> kotlin.collections.List&lt;ContactDto&gt; createTmpContacts(contactDto)

Create a contact with the current user

Returns an instance of created contact.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val contactDto : kotlin.collections.List<ContactDto> =  // kotlin.collections.List<ContactDto> | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.createTmpContacts(contactDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpContacts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpContacts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactDto** | [**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpDatabase"></a>
# **createTmpDatabase**
> kotlin.Any createTmpDatabase()

Create tmp database for current user

Nothing happens if the database already exists

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
try {
    val result : kotlin.Any = apiInstance.createTmpDatabase()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpDatabase")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpDatabase")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="createTmpDocument"></a>
# **createTmpDocument**
> DocumentDto createTmpDocument(documentDto)

Create a document with the current user

Returns an instance of created document.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val documentDto : DocumentDto =  // DocumentDto | 
try {
    val result : DocumentDto = apiInstance.createTmpDocument(documentDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpDocument")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpDocument")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentDto** | [**DocumentDto**](DocumentDto.md)|  |

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpDocuments"></a>
# **createTmpDocuments**
> kotlin.collections.List&lt;DocumentDto&gt; createTmpDocuments(documentDto)

Create a document with the current user

Returns an instance of created document.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val documentDto : kotlin.collections.List<DocumentDto> =  // kotlin.collections.List<DocumentDto> | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.createTmpDocuments(documentDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpDocuments")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpDocuments")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentDto** | [**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)|  |

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpEntityTemplate"></a>
# **createTmpEntityTemplate**
> EntityTemplateDto createTmpEntityTemplate(entityTemplateDto)

Create a entityTemplate with the current user

Returns an instance of created entityTemplate.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val entityTemplateDto : EntityTemplateDto =  // EntityTemplateDto | 
try {
    val result : EntityTemplateDto = apiInstance.createTmpEntityTemplate(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpEntityTemplate")
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

<a name="createTmpEntityTemplates"></a>
# **createTmpEntityTemplates**
> kotlin.collections.List&lt;EntityTemplateDto&gt; createTmpEntityTemplates(entityTemplateDto)

Create a entityTemplate with the current user

Returns an instance of created entityTemplate.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val entityTemplateDto : kotlin.collections.List<EntityTemplateDto> =  // kotlin.collections.List<EntityTemplateDto> | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.createTmpEntityTemplates(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpEntityTemplates")
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

<a name="createTmpForm"></a>
# **createTmpForm**
> FormDto createTmpForm(formDto)

Create a form with the current user

Returns an instance of created form.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val formDto : FormDto =  // FormDto | 
try {
    val result : FormDto = apiInstance.createTmpForm(formDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpForm")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpForm")
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

<a name="createTmpForms"></a>
# **createTmpForms**
> kotlin.collections.List&lt;FormDto&gt; createTmpForms(formDto)

Create a form with the current user

Returns an instance of created form.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val formDto : kotlin.collections.List<FormDto> =  // kotlin.collections.List<FormDto> | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.createTmpForms(formDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpForms")
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

<a name="createTmpHealthElement"></a>
# **createTmpHealthElement**
> HealthElementDto createTmpHealthElement(healthElementDto)

Create a healthElement with the current user

Returns an instance of created healthElement.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val healthElementDto : HealthElementDto =  // HealthElementDto | 
try {
    val result : HealthElementDto = apiInstance.createTmpHealthElement(healthElementDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpHealthElement")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpHealthElement")
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

<a name="createTmpHealthElements"></a>
# **createTmpHealthElements**
> kotlin.collections.List&lt;HealthElementDto&gt; createTmpHealthElements(healthElementDto)

Create a healthElement with the current user

Returns an instance of created healthElement.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val healthElementDto : kotlin.collections.List<HealthElementDto> =  // kotlin.collections.List<HealthElementDto> | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.createTmpHealthElements(healthElementDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpHealthElements")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpHealthElements")
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

<a name="createTmpInvoice"></a>
# **createTmpInvoice**
> InvoiceDto createTmpInvoice(invoiceDto)

Create a invoice with the current user

Returns an instance of created invoice.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val invoiceDto : InvoiceDto =  // InvoiceDto | 
try {
    val result : InvoiceDto = apiInstance.createTmpInvoice(invoiceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpInvoice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpInvoice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceDto** | [**InvoiceDto**](InvoiceDto.md)|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpInvoices"></a>
# **createTmpInvoices**
> kotlin.collections.List&lt;InvoiceDto&gt; createTmpInvoices(invoiceDto)

Create a invoice with the current user

Returns an instance of created invoice.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val invoiceDto : kotlin.collections.List<InvoiceDto> =  // kotlin.collections.List<InvoiceDto> | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.createTmpInvoices(invoiceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpInvoices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpInvoices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceDto** | [**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpMessage"></a>
# **createTmpMessage**
> MessageDto createTmpMessage(messageDto)

Create a message with the current user

Returns an instance of created message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val messageDto : MessageDto =  // MessageDto | 
try {
    val result : MessageDto = apiInstance.createTmpMessage(messageDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpMessage")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpMessage")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageDto** | [**MessageDto**](MessageDto.md)|  |

### Return type

[**MessageDto**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpMessages"></a>
# **createTmpMessages**
> kotlin.collections.List&lt;MessageDto&gt; createTmpMessages(messageDto)

Create a message with the current user

Returns an instance of created message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val messageDto : kotlin.collections.List<MessageDto> =  // kotlin.collections.List<MessageDto> | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.createTmpMessages(messageDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpMessages")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpMessages")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageDto** | [**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpPatient"></a>
# **createTmpPatient**
> PatientDto createTmpPatient(patientDto)

Create a patient with the current user

Returns an instance of created patient.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val patientDto : PatientDto =  // PatientDto | 
try {
    val result : PatientDto = apiInstance.createTmpPatient(patientDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpPatient")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpPatient")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientDto** | [**PatientDto**](PatientDto.md)|  |

### Return type

[**PatientDto**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createTmpPatients"></a>
# **createTmpPatients**
> kotlin.collections.List&lt;PatientDto&gt; createTmpPatients(patientDto)

Create a patient with the current user

Returns an instance of created patient.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val patientDto : kotlin.collections.List<PatientDto> =  // kotlin.collections.List<PatientDto> | 
try {
    val result : kotlin.collections.List<PatientDto> = apiInstance.createTmpPatients(patientDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#createTmpPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#createTmpPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientDto** | [**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)|  |

### Return type

[**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteTmpItems"></a>
# **deleteTmpItems**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteTmpItems(requestBody)

Soft delete items.

Response is a set containing the ID&#39;s of deleted items.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteTmpItems(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#deleteTmpItems")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#deleteTmpItems")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="destroyTmpDatabase"></a>
# **destroyTmpDatabase**
> kotlin.Any destroyTmpDatabase()

Destroy tmp database for current user

Nothing happens if the database does not exists

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
try {
    val result : kotlin.Any = apiInstance.destroyTmpDatabase()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#destroyTmpDatabase")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#destroyTmpDatabase")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpClassification"></a>
# **getTmpClassification**
> ClassificationDto getTmpClassification(id)

Get a classification by id

Returns an instance of classification.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : ClassificationDto = apiInstance.getTmpClassification(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpClassification")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpClassification")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**ClassificationDto**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpClassifications"></a>
# **getTmpClassifications**
> kotlin.collections.List&lt;ClassificationDto&gt; getTmpClassifications(requestBody)

Get classifications by ids with the current user

Returns an instance of created classification.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<ClassificationDto> = apiInstance.getTmpClassifications(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpClassifications")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpClassifications")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;ClassificationDto&gt;**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getTmpContact"></a>
# **getTmpContact**
> ContactDto getTmpContact(id)

Get a contact by id

Returns an instance of contact.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : ContactDto = apiInstance.getTmpContact(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpContact")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpContact")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**ContactDto**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpContacts"></a>
# **getTmpContacts**
> kotlin.collections.List&lt;ContactDto&gt; getTmpContacts(requestBody)

Get contacts by ids with the current user

Returns an instance of created contact.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.getTmpContacts(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpContacts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpContacts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getTmpDocument"></a>
# **getTmpDocument**
> DocumentDto getTmpDocument(id)

Get a document by id

Returns an instance of document.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : DocumentDto = apiInstance.getTmpDocument(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpDocument")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpDocument")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpDocuments"></a>
# **getTmpDocuments**
> kotlin.collections.List&lt;DocumentDto&gt; getTmpDocuments(requestBody)

Get documents by ids with the current user

Returns an instance of created document.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.getTmpDocuments(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpDocuments")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpDocuments")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getTmpEntityTemplate"></a>
# **getTmpEntityTemplate**
> EntityTemplateDto getTmpEntityTemplate(id)

Get a entityTemplate by id

Returns an instance of entityTemplate.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : EntityTemplateDto = apiInstance.getTmpEntityTemplate(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpEntityTemplate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**EntityTemplateDto**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpEntityTemplates"></a>
# **getTmpEntityTemplates**
> kotlin.collections.List&lt;EntityTemplateDto&gt; getTmpEntityTemplates(requestBody)

Get entityTemplates by ids with the current user

Returns an instance of created entityTemplate.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.getTmpEntityTemplates(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpEntityTemplates")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;EntityTemplateDto&gt;**](EntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getTmpForm"></a>
# **getTmpForm**
> FormDto getTmpForm(id)

Get a form by id

Returns an instance of form.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : FormDto = apiInstance.getTmpForm(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpForm")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpForm")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**FormDto**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpForms"></a>
# **getTmpForms**
> kotlin.collections.List&lt;FormDto&gt; getTmpForms(requestBody)

Get forms by ids with the current user

Returns an instance of created form.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.getTmpForms(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpForms")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;FormDto&gt;**](FormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getTmpHealthElement"></a>
# **getTmpHealthElement**
> HealthElementDto getTmpHealthElement(id)

Get a healthElement by id

Returns an instance of healthElement.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : HealthElementDto = apiInstance.getTmpHealthElement(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpHealthElement")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpHealthElement")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**HealthElementDto**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpHealthElements"></a>
# **getTmpHealthElements**
> kotlin.collections.List&lt;HealthElementDto&gt; getTmpHealthElements(requestBody)

Get healthElements by ids with the current user

Returns an instance of created healthElement.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.getTmpHealthElements(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpHealthElements")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpHealthElements")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;HealthElementDto&gt;**](HealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getTmpInvoice"></a>
# **getTmpInvoice**
> InvoiceDto getTmpInvoice(id)

Get a invoice by id

Returns an instance of invoice.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : InvoiceDto = apiInstance.getTmpInvoice(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpInvoice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpInvoice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpInvoices"></a>
# **getTmpInvoices**
> kotlin.collections.List&lt;InvoiceDto&gt; getTmpInvoices(requestBody)

Get invoices by ids with the current user

Returns an instance of created invoice.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.getTmpInvoices(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpInvoices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpInvoices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getTmpMessage"></a>
# **getTmpMessage**
> MessageDto getTmpMessage(id)

Get a message by id

Returns an instance of message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : MessageDto = apiInstance.getTmpMessage(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpMessage")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpMessage")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**MessageDto**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpMessages"></a>
# **getTmpMessages**
> kotlin.collections.List&lt;MessageDto&gt; getTmpMessages(requestBody)

Get messages by ids with the current user

Returns an instance of created message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.getTmpMessages(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpMessages")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpMessages")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getTmpPatient"></a>
# **getTmpPatient**
> PatientDto getTmpPatient(id)

Get a patient by id

Returns an instance of patient.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : PatientDto = apiInstance.getTmpPatient(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpPatient")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpPatient")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

[**PatientDto**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTmpPatients"></a>
# **getTmpPatients**
> kotlin.collections.List&lt;PatientDto&gt; getTmpPatients(requestBody)

Get patients by ids with the current user

Returns an instance of created patient.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<PatientDto> = apiInstance.getTmpPatients(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#getTmpPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#getTmpPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listTmpClassifications"></a>
# **listTmpClassifications**
> PaginatedListClassificationDto listTmpClassifications(firstClassificationId, pageSize)

List classifications with the current user

Returns paginated classifications.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val firstClassificationId : kotlin.String = firstClassificationId_example // kotlin.String | 
val pageSize : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListClassificationDto = apiInstance.listTmpClassifications(firstClassificationId, pageSize)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#listTmpClassifications")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#listTmpClassifications")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstClassificationId** | **kotlin.String**|  | [optional]
 **pageSize** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListClassificationDto**](PaginatedListClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listTmpContacts"></a>
# **listTmpContacts**
> PaginatedListInvoiceDto listTmpContacts(firstContactId, pageSize)

List contacts with the current user

Returns paginated contacts.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val firstContactId : kotlin.String = firstContactId_example // kotlin.String | 
val pageSize : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListInvoiceDto = apiInstance.listTmpContacts(firstContactId, pageSize)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#listTmpContacts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#listTmpContacts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstContactId** | **kotlin.String**|  | [optional]
 **pageSize** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListInvoiceDto**](PaginatedListInvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listTmpDocuments"></a>
# **listTmpDocuments**
> PaginatedListDocumentDto listTmpDocuments(firstDocumentId, pageSize)

List documents with the current user

Returns paginated documents.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val firstDocumentId : kotlin.String = firstDocumentId_example // kotlin.String | 
val pageSize : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListDocumentDto = apiInstance.listTmpDocuments(firstDocumentId, pageSize)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#listTmpDocuments")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#listTmpDocuments")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstDocumentId** | **kotlin.String**|  | [optional]
 **pageSize** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListDocumentDto**](PaginatedListDocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listTmpEntityTemplates"></a>
# **listTmpEntityTemplates**
> PaginatedListEntityTemplateDto listTmpEntityTemplates(firstEntityTemplateId, pageSize)

List entityTemplates with the current user

Returns paginated entityTemplates.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val firstEntityTemplateId : kotlin.String = firstEntityTemplateId_example // kotlin.String | 
val pageSize : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListEntityTemplateDto = apiInstance.listTmpEntityTemplates(firstEntityTemplateId, pageSize)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#listTmpEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#listTmpEntityTemplates")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstEntityTemplateId** | **kotlin.String**|  | [optional]
 **pageSize** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListEntityTemplateDto**](PaginatedListEntityTemplateDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listTmpForms"></a>
# **listTmpForms**
> PaginatedListFormDto listTmpForms(firstFormId, pageSize)

List forms with the current user

Returns paginated forms.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val firstFormId : kotlin.String = firstFormId_example // kotlin.String | 
val pageSize : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListFormDto = apiInstance.listTmpForms(firstFormId, pageSize)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#listTmpForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#listTmpForms")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstFormId** | **kotlin.String**|  | [optional]
 **pageSize** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListFormDto**](PaginatedListFormDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listTmpHealthElements"></a>
# **listTmpHealthElements**
> PaginatedListHealthElementDto listTmpHealthElements(firstHealthElementId, pageSize)

List healthElements with the current user

Returns paginated healthElements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val firstHealthElementId : kotlin.String = firstHealthElementId_example // kotlin.String | 
val pageSize : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListHealthElementDto = apiInstance.listTmpHealthElements(firstHealthElementId, pageSize)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#listTmpHealthElements")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#listTmpHealthElements")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstHealthElementId** | **kotlin.String**|  | [optional]
 **pageSize** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListHealthElementDto**](PaginatedListHealthElementDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listTmpInvoices"></a>
# **listTmpInvoices**
> PaginatedListInvoiceDto listTmpInvoices(firstInvoiceId, pageSize)

List invoices with the current user

Returns paginated invoices.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val firstInvoiceId : kotlin.String = firstInvoiceId_example // kotlin.String | 
val pageSize : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListInvoiceDto = apiInstance.listTmpInvoices(firstInvoiceId, pageSize)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#listTmpInvoices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#listTmpInvoices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstInvoiceId** | **kotlin.String**|  | [optional]
 **pageSize** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListInvoiceDto**](PaginatedListInvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listTmpMessages"></a>
# **listTmpMessages**
> PaginatedListInvoiceDto listTmpMessages(firstMessageId, pageSize)

List messages with the current user

Returns paginated messages.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val firstMessageId : kotlin.String = firstMessageId_example // kotlin.String | 
val pageSize : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListInvoiceDto = apiInstance.listTmpMessages(firstMessageId, pageSize)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#listTmpMessages")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#listTmpMessages")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstMessageId** | **kotlin.String**|  | [optional]
 **pageSize** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListInvoiceDto**](PaginatedListInvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listTmpPatients"></a>
# **listTmpPatients**
> PaginatedListPatientDto listTmpPatients(firstPatientId, pageSize)

List patients with the current user

Returns paginated patients.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val firstPatientId : kotlin.String = firstPatientId_example // kotlin.String | 
val pageSize : kotlin.Int = 56 // kotlin.Int | 
try {
    val result : PaginatedListPatientDto = apiInstance.listTmpPatients(firstPatientId, pageSize)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#listTmpPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#listTmpPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstPatientId** | **kotlin.String**|  | [optional]
 **pageSize** | **kotlin.Int**|  | [optional]

### Return type

[**PaginatedListPatientDto**](PaginatedListPatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyTmpClassification"></a>
# **modifyTmpClassification**
> ClassificationDto modifyTmpClassification(classificationDto)

Modify a classification

Returns the modified classification.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val classificationDto : ClassificationDto =  // ClassificationDto | 
try {
    val result : ClassificationDto = apiInstance.modifyTmpClassification(classificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpClassification")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpClassification")
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

<a name="modifyTmpClassifications"></a>
# **modifyTmpClassifications**
> kotlin.collections.List&lt;ClassificationDto&gt; modifyTmpClassifications(classificationDto)

Modify a batch of healthcare elements

Returns the modified healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val classificationDto : kotlin.collections.List<ClassificationDto> =  // kotlin.collections.List<ClassificationDto> | 
try {
    val result : kotlin.collections.List<ClassificationDto> = apiInstance.modifyTmpClassifications(classificationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpClassifications")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpClassifications")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **classificationDto** | [**kotlin.collections.List&lt;ClassificationDto&gt;**](ClassificationDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ClassificationDto&gt;**](ClassificationDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpContact"></a>
# **modifyTmpContact**
> ContactDto modifyTmpContact(contactDto)

Modify a contact

Returns the modified contact.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val contactDto : ContactDto =  // ContactDto | 
try {
    val result : ContactDto = apiInstance.modifyTmpContact(contactDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpContact")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpContact")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactDto** | [**ContactDto**](ContactDto.md)|  |

### Return type

[**ContactDto**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpContacts"></a>
# **modifyTmpContacts**
> kotlin.collections.List&lt;ContactDto&gt; modifyTmpContacts(contactDto)

Modify a batch of healthcare elements

Returns the modified healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val contactDto : kotlin.collections.List<ContactDto> =  // kotlin.collections.List<ContactDto> | 
try {
    val result : kotlin.collections.List<ContactDto> = apiInstance.modifyTmpContacts(contactDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpContacts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpContacts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **contactDto** | [**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)|  |

### Return type

[**kotlin.collections.List&lt;ContactDto&gt;**](ContactDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpDocument"></a>
# **modifyTmpDocument**
> DocumentDto modifyTmpDocument(documentDto)

Modify a document

Returns the modified document.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val documentDto : DocumentDto =  // DocumentDto | 
try {
    val result : DocumentDto = apiInstance.modifyTmpDocument(documentDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpDocument")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpDocument")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentDto** | [**DocumentDto**](DocumentDto.md)|  |

### Return type

[**DocumentDto**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpDocuments"></a>
# **modifyTmpDocuments**
> kotlin.collections.List&lt;DocumentDto&gt; modifyTmpDocuments(documentDto)

Modify a batch of healthcare elements

Returns the modified healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val documentDto : kotlin.collections.List<DocumentDto> =  // kotlin.collections.List<DocumentDto> | 
try {
    val result : kotlin.collections.List<DocumentDto> = apiInstance.modifyTmpDocuments(documentDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpDocuments")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpDocuments")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentDto** | [**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)|  |

### Return type

[**kotlin.collections.List&lt;DocumentDto&gt;**](DocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpEntityTemplate"></a>
# **modifyTmpEntityTemplate**
> EntityTemplateDto modifyTmpEntityTemplate(entityTemplateDto)

Modify a entityTemplate

Returns the modified entityTemplate.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val entityTemplateDto : EntityTemplateDto =  // EntityTemplateDto | 
try {
    val result : EntityTemplateDto = apiInstance.modifyTmpEntityTemplate(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpEntityTemplate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpEntityTemplate")
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

<a name="modifyTmpEntityTemplates"></a>
# **modifyTmpEntityTemplates**
> kotlin.collections.List&lt;EntityTemplateDto&gt; modifyTmpEntityTemplates(entityTemplateDto)

Modify a batch of healthcare elements

Returns the modified healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val entityTemplateDto : kotlin.collections.List<EntityTemplateDto> =  // kotlin.collections.List<EntityTemplateDto> | 
try {
    val result : kotlin.collections.List<EntityTemplateDto> = apiInstance.modifyTmpEntityTemplates(entityTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpEntityTemplates")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpEntityTemplates")
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

<a name="modifyTmpForm"></a>
# **modifyTmpForm**
> FormDto modifyTmpForm(formDto)

Modify a form

Returns the modified form.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val formDto : FormDto =  // FormDto | 
try {
    val result : FormDto = apiInstance.modifyTmpForm(formDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpForm")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpForm")
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

<a name="modifyTmpForms"></a>
# **modifyTmpForms**
> kotlin.collections.List&lt;FormDto&gt; modifyTmpForms(formDto)

Modify a batch of healthcare elements

Returns the modified healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val formDto : kotlin.collections.List<FormDto> =  // kotlin.collections.List<FormDto> | 
try {
    val result : kotlin.collections.List<FormDto> = apiInstance.modifyTmpForms(formDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpForms")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpForms")
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

<a name="modifyTmpHealthElement"></a>
# **modifyTmpHealthElement**
> HealthElementDto modifyTmpHealthElement(healthElementDto)

Modify a healthElement

Returns the modified healthElement.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val healthElementDto : HealthElementDto =  // HealthElementDto | 
try {
    val result : HealthElementDto = apiInstance.modifyTmpHealthElement(healthElementDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpHealthElement")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpHealthElement")
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

<a name="modifyTmpHealthElements"></a>
# **modifyTmpHealthElements**
> kotlin.collections.List&lt;HealthElementDto&gt; modifyTmpHealthElements(healthElementDto)

Modify a batch of healthcare elements

Returns the modified healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val healthElementDto : kotlin.collections.List<HealthElementDto> =  // kotlin.collections.List<HealthElementDto> | 
try {
    val result : kotlin.collections.List<HealthElementDto> = apiInstance.modifyTmpHealthElements(healthElementDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpHealthElements")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpHealthElements")
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

<a name="modifyTmpInvoice"></a>
# **modifyTmpInvoice**
> InvoiceDto modifyTmpInvoice(invoiceDto)

Modify a invoice

Returns the modified invoice.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val invoiceDto : InvoiceDto =  // InvoiceDto | 
try {
    val result : InvoiceDto = apiInstance.modifyTmpInvoice(invoiceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpInvoice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpInvoice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceDto** | [**InvoiceDto**](InvoiceDto.md)|  |

### Return type

[**InvoiceDto**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpInvoices"></a>
# **modifyTmpInvoices**
> kotlin.collections.List&lt;InvoiceDto&gt; modifyTmpInvoices(invoiceDto)

Modify a batch of healthcare elements

Returns the modified healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val invoiceDto : kotlin.collections.List<InvoiceDto> =  // kotlin.collections.List<InvoiceDto> | 
try {
    val result : kotlin.collections.List<InvoiceDto> = apiInstance.modifyTmpInvoices(invoiceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpInvoices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpInvoices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **invoiceDto** | [**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)|  |

### Return type

[**kotlin.collections.List&lt;InvoiceDto&gt;**](InvoiceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpMessage"></a>
# **modifyTmpMessage**
> MessageDto modifyTmpMessage(messageDto)

Modify a message

Returns the modified message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val messageDto : MessageDto =  // MessageDto | 
try {
    val result : MessageDto = apiInstance.modifyTmpMessage(messageDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpMessage")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpMessage")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageDto** | [**MessageDto**](MessageDto.md)|  |

### Return type

[**MessageDto**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpMessages"></a>
# **modifyTmpMessages**
> kotlin.collections.List&lt;MessageDto&gt; modifyTmpMessages(messageDto)

Modify a batch of healthcare elements

Returns the modified healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val messageDto : kotlin.collections.List<MessageDto> =  // kotlin.collections.List<MessageDto> | 
try {
    val result : kotlin.collections.List<MessageDto> = apiInstance.modifyTmpMessages(messageDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpMessages")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpMessages")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **messageDto** | [**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)|  |

### Return type

[**kotlin.collections.List&lt;MessageDto&gt;**](MessageDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpPatient"></a>
# **modifyTmpPatient**
> PatientDto modifyTmpPatient(patientDto)

Modify a patient

Returns the modified patient.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val patientDto : PatientDto =  // PatientDto | 
try {
    val result : PatientDto = apiInstance.modifyTmpPatient(patientDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpPatient")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpPatient")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientDto** | [**PatientDto**](PatientDto.md)|  |

### Return type

[**PatientDto**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyTmpPatients"></a>
# **modifyTmpPatients**
> kotlin.collections.List&lt;PatientDto&gt; modifyTmpPatients(patientDto)

Modify a batch of healthcare elements

Returns the modified healthcare elements.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val patientDto : kotlin.collections.List<PatientDto> =  // kotlin.collections.List<PatientDto> | 
try {
    val result : kotlin.collections.List<PatientDto> = apiInstance.modifyTmpPatients(patientDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#modifyTmpPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#modifyTmpPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientDto** | [**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)|  |

### Return type

[**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="purgeTmpItems"></a>
# **purgeTmpItems**
> kotlin.collections.List&lt;DocIdentifier&gt; purgeTmpItems(requestBody)

Hard delete items.

Response is a set containing the ID&#39;s of deleted items.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.purgeTmpItems(requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#purgeTmpItems")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#purgeTmpItems")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="replicateToTmpDatabase"></a>
# **replicateToTmpDatabase**
> ReplicatorDocumentDto replicateToTmpDatabase(from, requestBody)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = TmpApi()
val from : kotlin.String = from_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.String> =  // kotlin.collections.List<kotlin.String> | 
try {
    val result : ReplicatorDocumentDto = apiInstance.replicateToTmpDatabase(from, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling TmpApi#replicateToTmpDatabase")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling TmpApi#replicateToTmpDatabase")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **from** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.String&gt;**](kotlin.String.md)|  |

### Return type

[**ReplicatorDocumentDto**](ReplicatorDocumentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

