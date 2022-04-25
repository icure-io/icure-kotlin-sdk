# GroupApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createGroup**](GroupApi.md#createGroup) | **POST** /rest/v2/group/{id} | Create a group
[**findGroups**](GroupApi.md#findGroups) | **GET** /rest/v2/group/{id}/children | Find groups by parent
[**findGroupsWithContent**](GroupApi.md#findGroupsWithContent) | **GET** /rest/v2/group/{id}/children/search | Find groups by parent and content
[**getGroup**](GroupApi.md#getGroup) | **GET** /rest/v2/group/{id} | Get a group by id
[**getGroupsStorageInfos**](GroupApi.md#getGroupsStorageInfos) | **POST** /rest/v2/group/storage/info | Reset storage for group
[**getReplicationInfo1**](GroupApi.md#getReplicationInfo1) | **GET** /rest/v2/group/{id}/r | Get index info
[**initDesignDocs**](GroupApi.md#initDesignDocs) | **PUT** /rest/v2/group/{id}/dd | Init design docs
[**listGroups**](GroupApi.md#listGroups) | **GET** /rest/v2/group | List groups
[**modifyGroupName**](GroupApi.md#modifyGroupName) | **PUT** /rest/v2/group/{id}/name/{name} | Update group name
[**modifyGroupProperties**](GroupApi.md#modifyGroupProperties) | **PUT** /rest/v2/group/{id}/properties | Update group properties
[**registerNewGroupAdministrator**](GroupApi.md#registerNewGroupAdministrator) | **POST** /rest/v2/group/register/trial | Create a group
[**resetStorage**](GroupApi.md#resetStorage) | **POST** /rest/v2/group/{id}/reset/storage | Reset storage for group
[**setGroupPassword**](GroupApi.md#setGroupPassword) | **PUT** /rest/v2/group/{id}/password | Set group password
[**solveConflicts**](GroupApi.md#solveConflicts) | **POST** /rest/v2/group/{id}/conflicts | Solve conflicts for group


<a name="createGroup"></a>
# **createGroup**
> GroupDto createGroup(id, name, password, databaseInitialisationDto, server, q, n, superGroup)

Create a group

Create a new group and associated dbs.  The created group will be manageable by the users that belong to the same group as the one that called createGroup. Several tasks can be executed during the group creation like DB replications towards the created DBs, users creation and healthcare parties creation

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group, also used for subsequent authentication against the db (can only contain digits, letters, - and _)
val name : kotlin.String = name_example // kotlin.String | The name of the group
val password : kotlin.String = password_example // kotlin.String | The password of the group (can only contain digits, letters, - and _)
val databaseInitialisationDto : DatabaseInitialisationDto =  // DatabaseInitialisationDto | 
val server : kotlin.String = server_example // kotlin.String | The server on which the group dbs will be created
val q : kotlin.Int = 56 // kotlin.Int | The number of shards for patient and healthdata dbs : 3-8 is a recommended range of value
val n : kotlin.Int = 56 // kotlin.Int | The number of replications for other dbs : 3 is a recommended value
val superGroup : kotlin.String = superGroup_example // kotlin.String | Group parent
try {
    val result : GroupDto = apiInstance.createGroup(id, name, password, databaseInitialisationDto, server, q, n, superGroup)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#createGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#createGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group, also used for subsequent authentication against the db (can only contain digits, letters, - and _) |
 **name** | **kotlin.String**| The name of the group |
 **password** | **kotlin.String**| The password of the group (can only contain digits, letters, - and _) |
 **databaseInitialisationDto** | [**DatabaseInitialisationDto**](DatabaseInitialisationDto.md)|  |
 **server** | **kotlin.String**| The server on which the group dbs will be created | [optional]
 **q** | **kotlin.Int**| The number of shards for patient and healthdata dbs : 3-8 is a recommended range of value | [optional]
 **n** | **kotlin.Int**| The number of replications for other dbs : 3 is a recommended value | [optional]
 **superGroup** | **kotlin.String**| Group parent | [optional]

### Return type

[**GroupDto**](GroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findGroups"></a>
# **findGroups**
> PaginatedListGroupDto findGroups(id, startDocumentId, limit)

Find groups by parent

List groups that are the children of the group with th eprovided parent id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A grou document ID used as a cursor for pagination
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListGroupDto = apiInstance.findGroups(id, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#findGroups")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#findGroups")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |
 **startDocumentId** | **kotlin.String**| A grou document ID used as a cursor for pagination | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional] [default to 1000]

### Return type

[**PaginatedListGroupDto**](PaginatedListGroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findGroupsWithContent"></a>
# **findGroupsWithContent**
> PaginatedListGroupDto findGroupsWithContent(id, searchString, startKey, startDocumentId, limit)

Find groups by parent and content

List groups that are the children of the group with the provided parent id and that match the provided search string

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
val searchString : kotlin.String = searchString_example // kotlin.String | The string to search for in the group. Properties, name and id are scanned for the provided search string.
val startKey : kotlin.String = startKey_example // kotlin.String | The start key for pagination, depends on the filters used
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A group document ID used as a cursor for pagination
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListGroupDto = apiInstance.findGroupsWithContent(id, searchString, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#findGroupsWithContent")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#findGroupsWithContent")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |
 **searchString** | **kotlin.String**| The string to search for in the group. Properties, name and id are scanned for the provided search string. |
 **startKey** | **kotlin.String**| The start key for pagination, depends on the filters used | [optional]
 **startDocumentId** | **kotlin.String**| A group document ID used as a cursor for pagination | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional] [default to 1000]

### Return type

[**PaginatedListGroupDto**](PaginatedListGroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getGroup"></a>
# **getGroup**
> GroupDto getGroup(id)

Get a group by id

Get a group by id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
try {
    val result : GroupDto = apiInstance.getGroup(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#getGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#getGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |

### Return type

[**GroupDto**](GroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getGroupsStorageInfos"></a>
# **getGroupsStorageInfos**
> kotlin.collections.List&lt;GroupDatabasesInfoDto&gt; getGroupsStorageInfos(listOfIdsDto)

Reset storage for group

Reset storage

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<GroupDatabasesInfoDto> = apiInstance.getGroupsStorageInfos(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#getGroupsStorageInfos")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#getGroupsStorageInfos")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;GroupDatabasesInfoDto&gt;**](GroupDatabasesInfoDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getReplicationInfo1"></a>
# **getReplicationInfo1**
> ReplicationInfoDto getReplicationInfo1(id)

Get index info

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
try {
    val result : ReplicationInfoDto = apiInstance.getReplicationInfo1(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#getReplicationInfo1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#getReplicationInfo1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |

### Return type

[**ReplicationInfoDto**](ReplicationInfoDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="initDesignDocs"></a>
# **initDesignDocs**
> kotlin.Any initDesignDocs(id, clazz, warmup)

Init design docs

Init design docs for provided group

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
val clazz : kotlin.String = clazz_example // kotlin.String | The class of the design doc
val warmup : kotlin.Boolean = true // kotlin.Boolean | Warmup the design doc
try {
    val result : kotlin.Any = apiInstance.initDesignDocs(id, clazz, warmup)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#initDesignDocs")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#initDesignDocs")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |
 **clazz** | **kotlin.String**| The class of the design doc | [optional]
 **warmup** | **kotlin.Boolean**| Warmup the design doc | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listGroups"></a>
# **listGroups**
> kotlin.collections.List&lt;GroupDto&gt; listGroups()

List groups

List existing groups

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
try {
    val result : kotlin.collections.List<GroupDto> = apiInstance.listGroups()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#listGroups")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#listGroups")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;GroupDto&gt;**](GroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyGroupName"></a>
# **modifyGroupName**
> GroupDto modifyGroupName(id, name)

Update group name

Update existing group name

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
val name : kotlin.String = name_example // kotlin.String | The new name for the group
try {
    val result : GroupDto = apiInstance.modifyGroupName(id, name)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#modifyGroupName")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#modifyGroupName")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |
 **name** | **kotlin.String**| The new name for the group |

### Return type

[**GroupDto**](GroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="modifyGroupProperties"></a>
# **modifyGroupProperties**
> GroupDto modifyGroupProperties(id, listOfPropertiesDto)

Update group properties

Update existing group properties

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
val listOfPropertiesDto : ListOfPropertiesDto =  // ListOfPropertiesDto | 
try {
    val result : GroupDto = apiInstance.modifyGroupProperties(id, listOfPropertiesDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#modifyGroupProperties")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#modifyGroupProperties")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |
 **listOfPropertiesDto** | [**ListOfPropertiesDto**](ListOfPropertiesDto.md)|  |

### Return type

[**GroupDto**](GroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="registerNewGroupAdministrator"></a>
# **registerNewGroupAdministrator**
> RegistrationSuccessDto registerNewGroupAdministrator(registrationInformationDto)

Create a group

Create a new group and associated dbs.  The created group will be manageable by the users that belong to the same group as the one that called createGroup. Several tasks can be executed during the group creation like DB replications towards the created DBs, users creation and healthcare parties creation

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val registrationInformationDto : RegistrationInformationDto =  // RegistrationInformationDto | 
try {
    val result : RegistrationSuccessDto = apiInstance.registerNewGroupAdministrator(registrationInformationDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#registerNewGroupAdministrator")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#registerNewGroupAdministrator")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **registrationInformationDto** | [**RegistrationInformationDto**](RegistrationInformationDto.md)|  |

### Return type

[**RegistrationSuccessDto**](RegistrationSuccessDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="resetStorage"></a>
# **resetStorage**
> kotlin.Any resetStorage(id, listOfIdsDto, q, n)

Reset storage for group

Reset storage

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
val q : kotlin.Int = 56 // kotlin.Int | The number of shards for patient and healthdata dbs : 3-8 is a recommended range of value
val n : kotlin.Int = 56 // kotlin.Int | The number of replications for dbs : 3 is a recommended value
try {
    val result : kotlin.Any = apiInstance.resetStorage(id, listOfIdsDto, q, n)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#resetStorage")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#resetStorage")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |
 **q** | **kotlin.Int**| The number of shards for patient and healthdata dbs : 3-8 is a recommended range of value | [optional]
 **n** | **kotlin.Int**| The number of replications for dbs : 3 is a recommended value | [optional]

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setGroupPassword"></a>
# **setGroupPassword**
> GroupDto setGroupPassword(id, password)

Set group password

Update password for provided group

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
val password : kotlin.String = password_example // kotlin.String | The new password for the group (can only contain digits, letters, - and _)
try {
    val result : GroupDto = apiInstance.setGroupPassword(id, password)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#setGroupPassword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#setGroupPassword")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |
 **password** | **kotlin.String**| The new password for the group (can only contain digits, letters, - and _) |

### Return type

[**GroupDto**](GroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="solveConflicts"></a>
# **solveConflicts**
> kotlin.collections.List&lt;IdWithRevDto&gt; solveConflicts(id, limit, warmup)

Solve conflicts for group

Solve conflicts for group

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = GroupApi()
val id : kotlin.String = id_example // kotlin.String | The id of the group
val limit : kotlin.Int = 56 // kotlin.Int | Solve at most limit conflicts
val warmup : kotlin.Boolean = true // kotlin.Boolean | Warmup the design doc
try {
    val result : kotlin.collections.List<IdWithRevDto> = apiInstance.solveConflicts(id, limit, warmup)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling GroupApi#solveConflicts")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling GroupApi#solveConflicts")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**| The id of the group |
 **limit** | **kotlin.Int**| Solve at most limit conflicts | [optional]
 **warmup** | **kotlin.Boolean**| Warmup the design doc | [optional]

### Return type

[**kotlin.collections.List&lt;IdWithRevDto&gt;**](IdWithRevDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

