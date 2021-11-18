# PatientApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**countOfPatients**](PatientApi.md#countOfPatients) | **GET** /rest/v2/patient/hcParty/{hcPartyId}/count | Get count of patients for a specific HcParty or for the current HcParty 
[**createPatient**](PatientApi.md#createPatient) | **POST** /rest/v2/patient | Create a patient
[**createPatients**](PatientApi.md#createPatients) | **POST** /rest/v2/patient/batch | Create patients in bulk
[**deletePatients**](PatientApi.md#deletePatients) | **POST** /rest/v2/patient/delete/batch | Delete patients.
[**filterPatientsBy**](PatientApi.md#filterPatientsBy) | **POST** /rest/v2/patient/filter | Filter patients for the current user (HcParty) 
[**findDeletedPatients**](PatientApi.md#findDeletedPatients) | **GET** /rest/v2/patient/deleted/byDate | Find deleted patients
[**findPatientsByAccessLogUserAfterDate**](PatientApi.md#findPatientsByAccessLogUserAfterDate) | **GET** /rest/v2/patient/byAccess/{userId} | Get Paginated List of Patients sorted by Access logs descending
[**findPatientsByHealthcareParty**](PatientApi.md#findPatientsByHealthcareParty) | **GET** /rest/v2/patient | List patients for a specific HcParty
[**findPatientsByNameBirthSsinAuto**](PatientApi.md#findPatientsByNameBirthSsinAuto) | **GET** /rest/v2/patient/byNameBirthSsinAuto | Find patients for the current user (HcParty) 
[**findPatientsIdsByHealthcareParty**](PatientApi.md#findPatientsIdsByHealthcareParty) | **GET** /rest/v2/patient/byHcPartyId | List patients by pages for a specific HcParty
[**findPatientsModifiedAfter**](PatientApi.md#findPatientsModifiedAfter) | **GET** /rest/v2/patient/modifiedAfter/{date} | List patients that have been modified after the provided date
[**fuzzySearch**](PatientApi.md#fuzzySearch) | **GET** /rest/v2/patient/fuzzy | Filter patients for the current user (HcParty) 
[**getPatient**](PatientApi.md#getPatient) | **GET** /rest/v2/patient/{patientId} | Get patient
[**getPatientByExternalId**](PatientApi.md#getPatientByExternalId) | **GET** /rest/v2/patient/byExternalId/{externalId} | Get the patient having the provided externalId
[**getPatientByHealthcarepartyAndIdentifier**](PatientApi.md#getPatientByHealthcarepartyAndIdentifier) | **GET** /rest/v2/patient/{hcPartyId}/{id} | Get patient by identifier
[**getPatientHcPartyKeysForDelegate**](PatientApi.md#getPatientHcPartyKeysForDelegate) | **GET** /rest/v2/patient/{patientId}/keys | Get the patient (identified by patientId) hcparty keys. Those keys are AES keys (encrypted) used to share information between HCPs and a patient.
[**getPatients**](PatientApi.md#getPatients) | **POST** /rest/v2/patient/byIds | Get patients by id
[**listDeletedPatientsByName**](PatientApi.md#listDeletedPatientsByName) | **GET** /rest/v2/patient/deleted/by_name | Find deleted patients
[**listOfMergesAfter**](PatientApi.md#listOfMergesAfter) | **GET** /rest/v2/patient/merges/{date} | List patients that have been merged towards another patient 
[**matchPatientsBy**](PatientApi.md#matchPatientsBy) | **POST** /rest/v2/patient/match | Get ids of patients matching the provided filter for the current user (HcParty) 
[**mergeInto**](PatientApi.md#mergeInto) | **PUT** /rest/v2/patient/mergeInto/{toId}/from/{fromIds} | Merge a series of patients into another patient
[**modifyPatient**](PatientApi.md#modifyPatient) | **PUT** /rest/v2/patient | Modify a patient
[**modifyPatientReferral**](PatientApi.md#modifyPatientReferral) | **PUT** /rest/v2/patient/{patientId}/referral/{referralId} | Set a patient referral doctor
[**modifyPatients**](PatientApi.md#modifyPatients) | **PUT** /rest/v2/patient/batch | Modify patients in bulk
[**newPatientDelegations**](PatientApi.md#newPatientDelegations) | **POST** /rest/v2/patient/{patientId}/delegate | Delegates a patients to a healthcare party
[**registerPatient**](PatientApi.md#registerPatient) | **POST** /rest/v2/patient/register/forHcp/{hcPartyId}/inGroup/{groupId} | Register a patient
[**undeletePatient**](PatientApi.md#undeletePatient) | **PUT** /rest/v2/patient/undelete/{patientIds} | undelete previously deleted patients


<a name="countOfPatients"></a>
# **countOfPatients**
> ContentDto countOfPatients(hcPartyId)

Get count of patients for a specific HcParty or for the current HcParty 

Returns the count of patients

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | Healthcare party id
try {
    val result : ContentDto = apiInstance.countOfPatients(hcPartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#countOfPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#countOfPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**| Healthcare party id |

### Return type

[**ContentDto**](ContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="createPatient"></a>
# **createPatient**
> PatientDto createPatient(patientDto)

Create a patient

Name, last name, date of birth, and gender are required. After creation of the patient and obtaining the ID, you need to create an initial delegation.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val patientDto : PatientDto =  // PatientDto | 
try {
    val result : PatientDto = apiInstance.createPatient(patientDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#createPatient")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#createPatient")
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

<a name="createPatients"></a>
# **createPatients**
> kotlin.collections.List&lt;IdWithRevDto&gt; createPatients(patientDto)

Create patients in bulk

Returns the id and _rev of created patients

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val patientDto : kotlin.collections.List<PatientDto> =  // kotlin.collections.List<PatientDto> | 
try {
    val result : kotlin.collections.List<IdWithRevDto> = apiInstance.createPatients(patientDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#createPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#createPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientDto** | [**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)|  |

### Return type

[**kotlin.collections.List&lt;IdWithRevDto&gt;**](IdWithRevDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deletePatients"></a>
# **deletePatients**
> kotlin.collections.List&lt;DocIdentifier&gt; deletePatients(listOfIdsDto)

Delete patients.

Response is an array containing the ID of deleted patient..

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deletePatients(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#deletePatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#deletePatients")
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

<a name="filterPatientsBy"></a>
# **filterPatientsBy**
> PaginatedListPatientDto filterPatientsBy(filterChainPatient, startKey, startDocumentId, limit, skip, sort, desc)

Filter patients for the current user (HcParty) 

Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val filterChainPatient : FilterChainPatient =  // FilterChainPatient | 
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination, depends on the filters used
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val skip : kotlin.Int = 56 // kotlin.Int | Skip rows
val sort : kotlin.String = sort_example // kotlin.String | Sort key
val desc : kotlin.Boolean = true // kotlin.Boolean | Descending
try {
    val result : PaginatedListPatientDto = apiInstance.filterPatientsBy(filterChainPatient, startKey, startDocumentId, limit, skip, sort, desc)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#filterPatientsBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#filterPatientsBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterChainPatient** | [**FilterChainPatient**](FilterChainPatient.md)|  |
 **startKey** | **kotlin.String**| The start key for pagination, depends on the filters used | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]
 **skip** | **kotlin.Int**| Skip rows | [optional]
 **sort** | **kotlin.String**| Sort key | [optional]
 **desc** | **kotlin.Boolean**| Descending | [optional]

### Return type

[**PaginatedListPatientDto**](PaginatedListPatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findDeletedPatients"></a>
# **findDeletedPatients**
> PaginatedListPatientDto findDeletedPatients(startDate, endDate, desc, startDocumentId, limit)

Find deleted patients

Returns a list of deleted patients, within the specified time period, if any.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val startDate : kotlin.Long = 789 // kotlin.Long | Filter deletions after this date (unix epoch), included
val endDate : kotlin.Long = 789 // kotlin.Long | Filter deletions before this date (unix epoch), included
val desc : kotlin.Boolean = true // kotlin.Boolean | Descending
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListPatientDto = apiInstance.findDeletedPatients(startDate, endDate, desc, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#findDeletedPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#findDeletedPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startDate** | **kotlin.Long**| Filter deletions after this date (unix epoch), included | [optional]
 **endDate** | **kotlin.Long**| Filter deletions before this date (unix epoch), included | [optional]
 **desc** | **kotlin.Boolean**| Descending | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListPatientDto**](PaginatedListPatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPatientsByAccessLogUserAfterDate"></a>
# **findPatientsByAccessLogUserAfterDate**
> PaginatedListPatientDto findPatientsByAccessLogUserAfterDate(userId, accessType, startDate, startKey, startDocumentId, limit)

Get Paginated List of Patients sorted by Access logs descending

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val userId : kotlin.String = userId_example // kotlin.String | A User ID
val accessType : kotlin.String = accessType_example // kotlin.String | The type of access (COMPUTER or USER)
val startDate : kotlin.Long = 789 // kotlin.Long | The start search epoch
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListPatientDto = apiInstance.findPatientsByAccessLogUserAfterDate(userId, accessType, startDate, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#findPatientsByAccessLogUserAfterDate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#findPatientsByAccessLogUserAfterDate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**| A User ID |
 **accessType** | **kotlin.String**| The type of access (COMPUTER or USER) | [optional]
 **startDate** | **kotlin.Long**| The start search epoch | [optional]
 **startKey** | **kotlin.String**| The start key for pagination | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional] [default to 1000]

### Return type

[**PaginatedListPatientDto**](PaginatedListPatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPatientsByHealthcareParty"></a>
# **findPatientsByHealthcareParty**
> PaginatedListPatientDto findPatientsByHealthcareParty(hcPartyId, sortField, startKey, startDocumentId, limit, sortDirection)

List patients for a specific HcParty

Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | Healthcare party id
val sortField : kotlin.String = sortField_example // kotlin.String | Optional value for sorting results by a given field ('name', 'ssin', 'dateOfBirth'). Specifying this deactivates filtering
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val sortDirection : kotlin.String = sortDirection_example // kotlin.String | Optional value for providing a sorting direction ('asc', 'desc'). Set to 'asc' by default.
try {
    val result : PaginatedListPatientDto = apiInstance.findPatientsByHealthcareParty(hcPartyId, sortField, startKey, startDocumentId, limit, sortDirection)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#findPatientsByHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#findPatientsByHealthcareParty")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**| Healthcare party id | [optional]
 **sortField** | **kotlin.String**| Optional value for sorting results by a given field (&#39;name&#39;, &#39;ssin&#39;, &#39;dateOfBirth&#39;). Specifying this deactivates filtering | [optional]
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]
 **sortDirection** | **kotlin.String**| Optional value for providing a sorting direction (&#39;asc&#39;, &#39;desc&#39;). Set to &#39;asc&#39; by default. | [optional] [default to &quot;asc&quot;]

### Return type

[**PaginatedListPatientDto**](PaginatedListPatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPatientsByNameBirthSsinAuto"></a>
# **findPatientsByNameBirthSsinAuto**
> PaginatedListPatientDto findPatientsByNameBirthSsinAuto(healthcarePartyId, filterValue, startKey, startDocumentId, limit, sortDirection)

Find patients for the current user (HcParty) 

Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val healthcarePartyId : kotlin.String = healthcarePartyId_example // kotlin.String | HealthcareParty Id, if unset will user user's hcpId
val filterValue : kotlin.String = filterValue_example // kotlin.String | Optional value for filtering results
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key's startKey
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val sortDirection : kotlin.String = sortDirection_example // kotlin.String | Optional value for providing a sorting direction ('asc', 'desc'). Set to 'asc' by default.
try {
    val result : PaginatedListPatientDto = apiInstance.findPatientsByNameBirthSsinAuto(healthcarePartyId, filterValue, startKey, startDocumentId, limit, sortDirection)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#findPatientsByNameBirthSsinAuto")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#findPatientsByNameBirthSsinAuto")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthcarePartyId** | **kotlin.String**| HealthcareParty Id, if unset will user user&#39;s hcpId | [optional]
 **filterValue** | **kotlin.String**| Optional value for filtering results | [optional]
 **startKey** | **kotlin.String**| The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#39;s startKey | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]
 **sortDirection** | **kotlin.String**| Optional value for providing a sorting direction (&#39;asc&#39;, &#39;desc&#39;). Set to &#39;asc&#39; by default. | [optional] [default to &quot;asc&quot;]

### Return type

[**PaginatedListPatientDto**](PaginatedListPatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPatientsIdsByHealthcareParty"></a>
# **findPatientsIdsByHealthcareParty**
> PaginatedListString findPatientsIdsByHealthcareParty(hcPartyId, startKey, startDocumentId, limit)

List patients by pages for a specific HcParty

Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | Healthcare party id
val startKey : kotlin.String = startKey_example // kotlin.String | The page first id
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Page size
try {
    val result : PaginatedListString = apiInstance.findPatientsIdsByHealthcareParty(hcPartyId, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#findPatientsIdsByHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#findPatientsIdsByHealthcareParty")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**| Healthcare party id |
 **startKey** | **kotlin.String**| The page first id | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Page size | [optional]

### Return type

[**PaginatedListString**](PaginatedListString.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findPatientsModifiedAfter"></a>
# **findPatientsModifiedAfter**
> PaginatedListPatientDto findPatientsModifiedAfter(date, startKey, startDocumentId, limit)

List patients that have been modified after the provided date

Returns a list of patients that have been modified after the provided date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val date : kotlin.Long = 789 // kotlin.Long | 
val startKey : kotlin.Long = 789 // kotlin.Long | The start key for pagination the date of the first element of the new page
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A patient document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListPatientDto = apiInstance.findPatientsModifiedAfter(date, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#findPatientsModifiedAfter")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#findPatientsModifiedAfter")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **date** | **kotlin.Long**|  |
 **startKey** | **kotlin.Long**| The start key for pagination the date of the first element of the new page | [optional]
 **startDocumentId** | **kotlin.String**| A patient document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListPatientDto**](PaginatedListPatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="fuzzySearch"></a>
# **fuzzySearch**
> kotlin.collections.List&lt;PatientDto&gt; fuzzySearch(firstName, lastName, dateOfBirth)

Filter patients for the current user (HcParty) 

Returns a list of patients

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val firstName : kotlin.String = firstName_example // kotlin.String | The first name
val lastName : kotlin.String = lastName_example // kotlin.String | The last name
val dateOfBirth : kotlin.Int = 56 // kotlin.Int | The date of birth
try {
    val result : kotlin.collections.List<PatientDto> = apiInstance.fuzzySearch(firstName, lastName, dateOfBirth)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#fuzzySearch")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#fuzzySearch")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstName** | **kotlin.String**| The first name | [optional]
 **lastName** | **kotlin.String**| The last name | [optional]
 **dateOfBirth** | **kotlin.Int**| The date of birth | [optional]

### Return type

[**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getPatient"></a>
# **getPatient**
> PatientDto getPatient(patientId)

Get patient

It gets patient administrative data.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
try {
    val result : PatientDto = apiInstance.getPatient(patientId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#getPatient")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#getPatient")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |

### Return type

[**PatientDto**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getPatientByExternalId"></a>
# **getPatientByExternalId**
> PatientDto getPatientByExternalId(externalId)

Get the patient having the provided externalId

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val externalId : kotlin.String = externalId_example // kotlin.String | A external ID
try {
    val result : PatientDto = apiInstance.getPatientByExternalId(externalId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#getPatientByExternalId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#getPatientByExternalId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **externalId** | **kotlin.String**| A external ID |

### Return type

[**PatientDto**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getPatientByHealthcarepartyAndIdentifier"></a>
# **getPatientByHealthcarepartyAndIdentifier**
> PatientDto getPatientByHealthcarepartyAndIdentifier(hcPartyId, id, system)

Get patient by identifier

It gets patient administrative data based on the identifier (root &amp; extension) parameters.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val system : kotlin.String = system_example // kotlin.String | 
try {
    val result : PatientDto = apiInstance.getPatientByHealthcarepartyAndIdentifier(hcPartyId, id, system)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#getPatientByHealthcarepartyAndIdentifier")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#getPatientByHealthcarepartyAndIdentifier")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **system** | **kotlin.String**|  | [optional]

### Return type

[**PatientDto**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getPatientHcPartyKeysForDelegate"></a>
# **getPatientHcPartyKeysForDelegate**
> kotlin.String getPatientHcPartyKeysForDelegate(patientId)

Get the patient (identified by patientId) hcparty keys. Those keys are AES keys (encrypted) used to share information between HCPs and a patient.

This endpoint is used to recover all keys that have already been created and that can be used to share information with this patient. It returns a map with the following structure: ID of the owner of the encrypted AES key -&gt; encrypted AES key. The returned encrypted AES keys will have to be decrypted using the patient&#39;s private key.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val patientId : kotlin.String = patientId_example // kotlin.String | The patient Id for which information is shared
try {
    val result : kotlin.String = apiInstance.getPatientHcPartyKeysForDelegate(patientId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#getPatientHcPartyKeysForDelegate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#getPatientHcPartyKeysForDelegate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**| The patient Id for which information is shared |

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getPatients"></a>
# **getPatients**
> kotlin.collections.List&lt;PatientDto&gt; getPatients(listOfIdsDto)

Get patients by id

It gets patient administrative data.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<PatientDto> = apiInstance.getPatients(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#getPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#getPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="listDeletedPatientsByName"></a>
# **listDeletedPatientsByName**
> kotlin.collections.List&lt;PatientDto&gt; listDeletedPatientsByName(firstName, lastName)

Find deleted patients

Returns a list of deleted patients, by name and/or firstname prefix, if any.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val firstName : kotlin.String = firstName_example // kotlin.String | First name prefix
val lastName : kotlin.String = lastName_example // kotlin.String | Last name prefix
try {
    val result : kotlin.collections.List<PatientDto> = apiInstance.listDeletedPatientsByName(firstName, lastName)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#listDeletedPatientsByName")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#listDeletedPatientsByName")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **firstName** | **kotlin.String**| First name prefix | [optional]
 **lastName** | **kotlin.String**| Last name prefix | [optional]

### Return type

[**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listOfMergesAfter"></a>
# **listOfMergesAfter**
> kotlin.collections.List&lt;PatientDto&gt; listOfMergesAfter(date)

List patients that have been merged towards another patient 

Returns a list of patients that have been merged after the provided date

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val date : kotlin.Long = 789 // kotlin.Long | 
try {
    val result : kotlin.collections.List<PatientDto> = apiInstance.listOfMergesAfter(date)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#listOfMergesAfter")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#listOfMergesAfter")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **date** | **kotlin.Long**|  |

### Return type

[**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="matchPatientsBy"></a>
# **matchPatientsBy**
> kotlin.collections.List&lt;kotlin.String&gt; matchPatientsBy(abstractFilterDtoPatient)

Get ids of patients matching the provided filter for the current user (HcParty) 

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val abstractFilterDtoPatient : AbstractFilterDtoPatient =  // AbstractFilterDtoPatient | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.matchPatientsBy(abstractFilterDtoPatient)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#matchPatientsBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#matchPatientsBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **abstractFilterDtoPatient** | [**AbstractFilterDtoPatient**](AbstractFilterDtoPatient.md)|  |

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="mergeInto"></a>
# **mergeInto**
> PatientDto mergeInto(toId, fromIds)

Merge a series of patients into another patient

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val toId : kotlin.String = toId_example // kotlin.String | 
val fromIds : kotlin.String = fromIds_example // kotlin.String | 
try {
    val result : PatientDto = apiInstance.mergeInto(toId, fromIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#mergeInto")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#mergeInto")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **toId** | **kotlin.String**|  |
 **fromIds** | **kotlin.String**|  |

### Return type

[**PatientDto**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyPatient"></a>
# **modifyPatient**
> PatientDto modifyPatient(patientDto)

Modify a patient

No particular return value. It&#39;s just a message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val patientDto : PatientDto =  // PatientDto | 
try {
    val result : PatientDto = apiInstance.modifyPatient(patientDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#modifyPatient")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#modifyPatient")
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

<a name="modifyPatientReferral"></a>
# **modifyPatientReferral**
> PatientDto modifyPatientReferral(patientId, referralId, start, end)

Set a patient referral doctor

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val referralId : kotlin.String = referralId_example // kotlin.String | The referal id. Accepts 'none' for referral removal.
val start : kotlin.Long = 789 // kotlin.Long | Optional value for start of referral
val end : kotlin.Long = 789 // kotlin.Long | Optional value for end of referral
try {
    val result : PatientDto = apiInstance.modifyPatientReferral(patientId, referralId, start, end)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#modifyPatientReferral")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#modifyPatientReferral")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **referralId** | **kotlin.String**| The referal id. Accepts &#39;none&#39; for referral removal. |
 **start** | **kotlin.Long**| Optional value for start of referral | [optional]
 **end** | **kotlin.Long**| Optional value for end of referral | [optional]

### Return type

[**PatientDto**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyPatients"></a>
# **modifyPatients**
> kotlin.collections.List&lt;IdWithRevDto&gt; modifyPatients(patientDto)

Modify patients in bulk

Returns the id and _rev of modified patients

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val patientDto : kotlin.collections.List<PatientDto> =  // kotlin.collections.List<PatientDto> | 
try {
    val result : kotlin.collections.List<IdWithRevDto> = apiInstance.modifyPatients(patientDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#modifyPatients")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#modifyPatients")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientDto** | [**kotlin.collections.List&lt;PatientDto&gt;**](PatientDto.md)|  |

### Return type

[**kotlin.collections.List&lt;IdWithRevDto&gt;**](IdWithRevDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="newPatientDelegations"></a>
# **newPatientDelegations**
> PatientDto newPatientDelegations(patientId, delegationDto)

Delegates a patients to a healthcare party

It delegates a patient to a healthcare party (By current healthcare party). A modified patient with new delegation gets returned.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val delegationDto : kotlin.collections.List<DelegationDto> =  // kotlin.collections.List<DelegationDto> | 
try {
    val result : PatientDto = apiInstance.newPatientDelegations(patientId, delegationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#newPatientDelegations")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#newPatientDelegations")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **delegationDto** | [**kotlin.collections.List&lt;DelegationDto&gt;**](DelegationDto.md)|  |

### Return type

[**PatientDto**](PatientDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="registerPatient"></a>
# **registerPatient**
> PatientRegistrationSuccessDto registerPatient(hcPartyId, groupId, patientDto)

Register a patient

Register a new patient into the system

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val hcPartyId : kotlin.String = hcPartyId_example // kotlin.String | 
val groupId : kotlin.String = groupId_example // kotlin.String | 
val patientDto : PatientDto =  // PatientDto | 
try {
    val result : PatientRegistrationSuccessDto = apiInstance.registerPatient(hcPartyId, groupId, patientDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#registerPatient")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#registerPatient")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **hcPartyId** | **kotlin.String**|  |
 **groupId** | **kotlin.String**|  |
 **patientDto** | [**PatientDto**](PatientDto.md)|  |

### Return type

[**PatientRegistrationSuccessDto**](PatientRegistrationSuccessDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="undeletePatient"></a>
# **undeletePatient**
> kotlin.collections.List&lt;DocIdentifier&gt; undeletePatient(patientIds)

undelete previously deleted patients

Response is an array containing the ID of undeleted patient..

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PatientApi()
val patientIds : kotlin.String = patientIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.undeletePatient(patientIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PatientApi#undeletePatient")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PatientApi#undeletePatient")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

