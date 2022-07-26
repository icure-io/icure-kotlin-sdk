# UserApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**assignHealthcareParty**](UserApi.md#assignHealthcareParty) | **PUT** /rest/v2/user/current/hcparty/{healthcarePartyId} | Assign a healthcare party ID to current user
[**checkPassword**](UserApi.md#checkPassword) | **GET** /rest/v2/user/checkPassword | 
[**checkTokenValidity**](UserApi.md#checkTokenValidity) | **GET** /rest/v2/user/token/{userId} | Check token validity
[**createUser**](UserApi.md#createUser) | **POST** /rest/v2/user | Create a user
[**createUserInGroup**](UserApi.md#createUserInGroup) | **POST** /rest/v2/user/inGroup/{groupId} | Create a user
[**deleteUser**](UserApi.md#deleteUser) | **DELETE** /rest/v2/user/{userId} | Delete a User based on his/her ID.
[**deleteUserInGroup**](UserApi.md#deleteUserInGroup) | **DELETE** /rest/v2/user/inGroup/{groupId}/{userId} | Delete a User based on his/her ID.
[**encodePassword**](UserApi.md#encodePassword) | **GET** /rest/v2/user/encodePassword | 
[**filterUsersBy**](UserApi.md#filterUsersBy) | **POST** /rest/v2/user/filter | Filter users for the current user (HcParty)
[**filterUsersInGroupBy**](UserApi.md#filterUsersInGroupBy) | **POST** /rest/v2/user/filter/inGroup/{groupId} | Filter users for the current user (HcParty) for a provided groupId
[**findByHcpartyId**](UserApi.md#findByHcpartyId) | **GET** /rest/v2/user/byHealthcarePartyId/{id} | Get the list of users by healthcare party id
[**findByPatientId**](UserApi.md#findByPatientId) | **GET** /rest/v2/user/byPatientId/{id} | Get the list of users by patient id
[**getCurrentSession**](UserApi.md#getCurrentSession) | **GET** /rest/v2/user/session | Get Currently logged-in user session.
[**getCurrentUser**](UserApi.md#getCurrentUser) | **GET** /rest/v2/user/current | Get presently logged-in user.
[**getMatchingUsers**](UserApi.md#getMatchingUsers) | **GET** /rest/v2/user/matches | Get presently logged-in user.
[**getToken**](UserApi.md#getToken) | **POST** /rest/v2/user/token/{userId}/{key} | Request a new temporary token for authentication
[**getTokenInAllGroups**](UserApi.md#getTokenInAllGroups) | **POST** /rest/v2/user/inAllGroups/token/{userIdentifier}/{key} | Require a new temporary token for authentication inside all groups
[**getTokenInGroup**](UserApi.md#getTokenInGroup) | **POST** /rest/v2/user/inGroup/{groupId}/token/{userId}/{key} | Require a new temporary token for authentication inside provided group
[**getUser**](UserApi.md#getUser) | **GET** /rest/v2/user/{userId} | Get a user by his ID
[**getUserByEmail**](UserApi.md#getUserByEmail) | **GET** /rest/v2/user/byEmail/{email} | Get a user by his Email/Login
[**listUsersBy**](UserApi.md#listUsersBy) | **GET** /rest/v2/user | List users with(out) pagination
[**listUsersInGroup**](UserApi.md#listUsersInGroup) | **GET** /rest/v2/user/inGroup/{groupId} | List users with(out) pagination
[**matchUsersBy**](UserApi.md#matchUsersBy) | **POST** /rest/v2/user/match | Get ids of healthcare party matching the provided filter for the current user (HcParty) 
[**modifyProperties**](UserApi.md#modifyProperties) | **PUT** /rest/v2/user/{userId}/properties | Modify a User property
[**modifyUser**](UserApi.md#modifyUser) | **PUT** /rest/v2/user | Modify a user.
[**modifyUserInGroup**](UserApi.md#modifyUserInGroup) | **PUT** /rest/v2/user/inGroup/{groupId} | Modify a user.


<a name="assignHealthcareParty"></a>
# **assignHealthcareParty**
> UserDto assignHealthcareParty(healthcarePartyId)

Assign a healthcare party ID to current user

UserDto gets returned.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val healthcarePartyId : kotlin.String = healthcarePartyId_example // kotlin.String | 
try {
    val result : UserDto = apiInstance.assignHealthcareParty(healthcarePartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#assignHealthcareParty")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#assignHealthcareParty")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **healthcarePartyId** | **kotlin.String**|  |

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="checkPassword"></a>
# **checkPassword**
> kotlin.Boolean checkPassword(password)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val password : kotlin.String = password_example // kotlin.String | 
try {
    val result : kotlin.Boolean = apiInstance.checkPassword(password)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#checkPassword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#checkPassword")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **password** | **kotlin.String**|  |

### Return type

**kotlin.Boolean**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="checkTokenValidity"></a>
# **checkTokenValidity**
> kotlin.Boolean checkTokenValidity(userId, token)

Check token validity

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val token : kotlin.String = token_example // kotlin.String | 
try {
    val result : kotlin.Boolean = apiInstance.checkTokenValidity(userId, token)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#checkTokenValidity")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#checkTokenValidity")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **token** | **kotlin.String**|  |

### Return type

**kotlin.Boolean**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="createUser"></a>
# **createUser**
> UserDto createUser(userDto)

Create a user

Create a user. HealthcareParty ID should be set. Email or Login have to be set. If login hasn&#39;t been set, Email will be used for Login instead.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val userDto : UserDto =  // UserDto | 
try {
    val result : UserDto = apiInstance.createUser(userDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#createUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#createUser")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userDto** | [**UserDto**](UserDto.md)|  |

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createUserInGroup"></a>
# **createUserInGroup**
> UserDto createUserInGroup(groupId, userDto)

Create a user

Create a user. HealthcareParty ID should be set. Email has to be set and the Login has to be null. On server-side, Email will be used for Login.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val userDto : UserDto =  // UserDto | 
try {
    val result : UserDto = apiInstance.createUserInGroup(groupId, userDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#createUserInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#createUserInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **userDto** | [**UserDto**](UserDto.md)|  |

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteUser"></a>
# **deleteUser**
> DocIdentifier deleteUser(userId)

Delete a User based on his/her ID.

Delete a User based on his/her ID. The return value is an array containing the ID of deleted user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val userId : kotlin.String = userId_example // kotlin.String | 
try {
    val result : DocIdentifier = apiInstance.deleteUser(userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#deleteUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#deleteUser")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |

### Return type

[**DocIdentifier**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deleteUserInGroup"></a>
# **deleteUserInGroup**
> kotlin.Any deleteUserInGroup(groupId, userId)

Delete a User based on his/her ID.

Delete a User based on his/her ID. The return value is an array containing the ID of deleted user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val userId : kotlin.String = userId_example // kotlin.String | 
try {
    val result : kotlin.Any = apiInstance.deleteUserInGroup(groupId, userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#deleteUserInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#deleteUserInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **userId** | **kotlin.String**|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="encodePassword"></a>
# **encodePassword**
> kotlin.String encodePassword(password)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val password : kotlin.String = password_example // kotlin.String | 
try {
    val result : kotlin.String = apiInstance.encodePassword(password)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#encodePassword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#encodePassword")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **password** | **kotlin.String**|  |

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="filterUsersBy"></a>
# **filterUsersBy**
> PaginatedListUserDto filterUsersBy(filterChainUser, startDocumentId, limit)

Filter users for the current user (HcParty)

Returns a list of users along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val filterChainUser : FilterChainUser =  // FilterChainUser | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A User document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListUserDto = apiInstance.filterUsersBy(filterChainUser, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#filterUsersBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#filterUsersBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterChainUser** | [**FilterChainUser**](FilterChainUser.md)|  |
 **startDocumentId** | **kotlin.String**| A User document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListUserDto**](PaginatedListUserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="filterUsersInGroupBy"></a>
# **filterUsersInGroupBy**
> PaginatedListUserDto filterUsersInGroupBy(groupId, filterChainUser, startDocumentId, limit)

Filter users for the current user (HcParty) for a provided groupId

Returns a list of users along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val filterChainUser : FilterChainUser =  // FilterChainUser | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A User document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListUserDto = apiInstance.filterUsersInGroupBy(groupId, filterChainUser, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#filterUsersInGroupBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#filterUsersInGroupBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **filterChainUser** | [**FilterChainUser**](FilterChainUser.md)|  |
 **startDocumentId** | **kotlin.String**| A User document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListUserDto**](PaginatedListUserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="findByHcpartyId"></a>
# **findByHcpartyId**
> kotlin.collections.List&lt;kotlin.String&gt; findByHcpartyId(id)

Get the list of users by healthcare party id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.findByHcpartyId(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#findByHcpartyId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#findByHcpartyId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="findByPatientId"></a>
# **findByPatientId**
> kotlin.collections.List&lt;kotlin.String&gt; findByPatientId(id)

Get the list of users by patient id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.findByPatientId(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#findByPatientId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#findByPatientId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **kotlin.String**|  |

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getCurrentSession"></a>
# **getCurrentSession**
> kotlin.String getCurrentSession()

Get Currently logged-in user session.

Get current user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
try {
    val result : kotlin.String = apiInstance.getCurrentSession()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getCurrentSession")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getCurrentSession")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: text/plain

<a name="getCurrentUser"></a>
# **getCurrentUser**
> UserDto getCurrentUser()

Get presently logged-in user.

Get current user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
try {
    val result : UserDto = apiInstance.getCurrentUser()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getCurrentUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getCurrentUser")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getMatchingUsers"></a>
# **getMatchingUsers**
> kotlin.collections.List&lt;UserGroupDto&gt; getMatchingUsers()

Get presently logged-in user.

Get current user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
try {
    val result : kotlin.collections.List<UserGroupDto> = apiInstance.getMatchingUsers()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getMatchingUsers")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getMatchingUsers")
    e.printStackTrace()
}
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**kotlin.collections.List&lt;UserGroupDto&gt;**](UserGroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getToken"></a>
# **getToken**
> kotlin.String getToken(userId, key, tokenValidity)

Request a new temporary token for authentication

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val key : kotlin.String = key_example // kotlin.String | The token key. Only one instance of a token with a defined key can exist at the same time
val tokenValidity : kotlin.Long = 789 // kotlin.Long | The token validity in seconds
try {
    val result : kotlin.String = apiInstance.getToken(userId, key, tokenValidity)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getToken")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getToken")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **key** | **kotlin.String**| The token key. Only one instance of a token with a defined key can exist at the same time |
 **tokenValidity** | **kotlin.Long**| The token validity in seconds | [optional]

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTokenInAllGroups"></a>
# **getTokenInAllGroups**
> kotlin.collections.List&lt;TokenWithGroupDto&gt; getTokenInAllGroups(userIdentifier, key, token, tokenValidity)

Require a new temporary token for authentication inside all groups

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val userIdentifier : kotlin.String = userIdentifier_example // kotlin.String | 
val key : kotlin.String = key_example // kotlin.String | The token key. Only one instance of a token with a defined key can exist at the same time
val token : kotlin.String = token_example // kotlin.String | 
val tokenValidity : kotlin.Long = 789 // kotlin.Long | The token validity in seconds
try {
    val result : kotlin.collections.List<TokenWithGroupDto> = apiInstance.getTokenInAllGroups(userIdentifier, key, token, tokenValidity)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getTokenInAllGroups")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getTokenInAllGroups")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userIdentifier** | **kotlin.String**|  |
 **key** | **kotlin.String**| The token key. Only one instance of a token with a defined key can exist at the same time |
 **token** | **kotlin.String**|  | [optional]
 **tokenValidity** | **kotlin.Long**| The token validity in seconds | [optional]

### Return type

[**kotlin.collections.List&lt;TokenWithGroupDto&gt;**](TokenWithGroupDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getTokenInGroup"></a>
# **getTokenInGroup**
> kotlin.String getTokenInGroup(groupId, userId, key, token, tokenValidity)

Require a new temporary token for authentication inside provided group

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val userId : kotlin.String = userId_example // kotlin.String | 
val key : kotlin.String = key_example // kotlin.String | The token key. Only one instance of a token with a defined key can exist at the same time
val token : kotlin.String = token_example // kotlin.String | 
val tokenValidity : kotlin.Long = 789 // kotlin.Long | The token validity in seconds
try {
    val result : kotlin.String = apiInstance.getTokenInGroup(groupId, userId, key, token, tokenValidity)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getTokenInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getTokenInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **userId** | **kotlin.String**|  |
 **key** | **kotlin.String**| The token key. Only one instance of a token with a defined key can exist at the same time |
 **token** | **kotlin.String**|  | [optional]
 **tokenValidity** | **kotlin.Long**| The token validity in seconds | [optional]

### Return type

**kotlin.String**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getUser"></a>
# **getUser**
> UserDto getUser(userId)

Get a user by his ID

General information about the user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val userId : kotlin.String = userId_example // kotlin.String | 
try {
    val result : UserDto = apiInstance.getUser(userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getUser")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getUserByEmail"></a>
# **getUserByEmail**
> UserDto getUserByEmail(email)

Get a user by his Email/Login

General information about the user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val email : kotlin.String = email_example // kotlin.String | 
try {
    val result : UserDto = apiInstance.getUserByEmail(email)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getUserByEmail")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getUserByEmail")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **email** | **kotlin.String**|  |

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listUsersBy"></a>
# **listUsersBy**
> PaginatedListUserDto listUsersBy(startKey, startDocumentId, limit, skipPatients)

List users with(out) pagination

Returns a list of users.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val startKey : kotlin.String = startKey_example // kotlin.String | An user email
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | An user document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
val skipPatients : kotlin.Boolean = true // kotlin.Boolean | Filter out patient users
try {
    val result : PaginatedListUserDto = apiInstance.listUsersBy(startKey, startDocumentId, limit, skipPatients)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#listUsersBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#listUsersBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startKey** | **kotlin.String**| An user email | [optional]
 **startDocumentId** | **kotlin.String**| An user document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]
 **skipPatients** | **kotlin.Boolean**| Filter out patient users | [optional]

### Return type

[**PaginatedListUserDto**](PaginatedListUserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listUsersInGroup"></a>
# **listUsersInGroup**
> PaginatedListUserDto listUsersInGroup(groupId, startKey, startDocumentId, limit)

List users with(out) pagination

Returns a list of users.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val startKey : kotlin.String = startKey_example // kotlin.String | An user login
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | An user document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListUserDto = apiInstance.listUsersInGroup(groupId, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#listUsersInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#listUsersInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **startKey** | **kotlin.String**| An user login | [optional]
 **startDocumentId** | **kotlin.String**| An user document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListUserDto**](PaginatedListUserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="matchUsersBy"></a>
# **matchUsersBy**
> kotlin.collections.List&lt;kotlin.String&gt; matchUsersBy(abstractFilterDtoUser)

Get ids of healthcare party matching the provided filter for the current user (HcParty) 

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val abstractFilterDtoUser : AbstractFilterDtoUser =  // AbstractFilterDtoUser | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.matchUsersBy(abstractFilterDtoUser)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#matchUsersBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#matchUsersBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **abstractFilterDtoUser** | [**AbstractFilterDtoUser**](AbstractFilterDtoUser.md)|  |

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyProperties"></a>
# **modifyProperties**
> UserDto modifyProperties(userId, propertyStubDto)

Modify a User property

Modify a User properties based on his/her ID. The return value is the modified user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val propertyStubDto : kotlin.collections.List<PropertyStubDto> =  // kotlin.collections.List<PropertyStubDto> | 
try {
    val result : UserDto = apiInstance.modifyProperties(userId, propertyStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#modifyProperties")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#modifyProperties")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **propertyStubDto** | [**kotlin.collections.List&lt;PropertyStubDto&gt;**](PropertyStubDto.md)|  | [optional]

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyUser"></a>
# **modifyUser**
> UserDto modifyUser(userDto)

Modify a user.

No particular return value. It&#39;s just a message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val userDto : UserDto =  // UserDto | 
try {
    val result : UserDto = apiInstance.modifyUser(userDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#modifyUser")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#modifyUser")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userDto** | [**UserDto**](UserDto.md)|  |

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyUserInGroup"></a>
# **modifyUserInGroup**
> UserDto modifyUserInGroup(groupId, userDto)

Modify a user.

No particular return value. It&#39;s just a message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val userDto : UserDto =  // UserDto | 
try {
    val result : UserDto = apiInstance.modifyUserInGroup(groupId, userDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#modifyUserInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#modifyUserInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **userDto** | [**UserDto**](UserDto.md)|  |

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

