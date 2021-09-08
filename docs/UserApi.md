# UserApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**assignHealthcareParty**](UserApi.md#assignHealthcareParty) | **PUT** /rest/v2/user/current/hcparty/{healthcarePartyId} | Assign a healthcare party ID to current user
[**assignHealthcareParty1**](UserApi.md#assignHealthcareParty1) | **PUT** /rest/v1/user/current/hcparty/{healthcarePartyId} | Assign a healthcare party ID to current user
[**checkPassword**](UserApi.md#checkPassword) | **GET** /rest/v2/user/checkPassword | 
[**checkPassword1**](UserApi.md#checkPassword1) | **GET** /rest/v1/user/checkPassword | 
[**createUser**](UserApi.md#createUser) | **POST** /rest/v2/user | Create a user
[**createUser1**](UserApi.md#createUser1) | **POST** /rest/v1/user | Create a user
[**createUserInGroup**](UserApi.md#createUserInGroup) | **POST** /rest/v2/user/inGroup/{groupId} | Create a user
[**createUserInGroup1**](UserApi.md#createUserInGroup1) | **POST** /rest/v1/user/inGroup/{groupId} | Create a user
[**deleteUser**](UserApi.md#deleteUser) | **DELETE** /rest/v2/user/{userId} | Delete a User based on his/her ID.
[**deleteUser1**](UserApi.md#deleteUser1) | **DELETE** /rest/v1/user/{userId} | Delete a User based on his/her ID.
[**deleteUserInGroup**](UserApi.md#deleteUserInGroup) | **DELETE** /rest/v2/user/inGroup/{groupId}/{userId} | Delete a User based on his/her ID.
[**deleteUserInGroup1**](UserApi.md#deleteUserInGroup1) | **DELETE** /rest/v1/user/inGroup/{groupId}/{userId} | Delete a User based on his/her ID.
[**encodePassword**](UserApi.md#encodePassword) | **GET** /rest/v2/user/encodePassword | 
[**encodePassword1**](UserApi.md#encodePassword1) | **GET** /rest/v1/user/encodePassword | 
[**findByHcpartyId**](UserApi.md#findByHcpartyId) | **GET** /rest/v2/user/byHealthcarePartyId/{id} | Get the list of users by healthcare party id
[**findByHcpartyId1**](UserApi.md#findByHcpartyId1) | **GET** /rest/v1/user/byHealthcarePartyId/{id} | Get the list of users by healthcare party id
[**forgottenPassword**](UserApi.md#forgottenPassword) | **POST** /rest/v2/user/forgottenPassword/{email} | Send a forgotten email message to an user
[**forgottenPassword1**](UserApi.md#forgottenPassword1) | **POST** /rest/v1/user/forgottenPassword/{email} | Send a forgotten email message to an user
[**getCurrentSession**](UserApi.md#getCurrentSession) | **GET** /rest/v2/user/session | Get Currently logged-in user session.
[**getCurrentSession1**](UserApi.md#getCurrentSession1) | **GET** /rest/v1/user/session | Get Currently logged-in user session.
[**getCurrentUser**](UserApi.md#getCurrentUser) | **GET** /rest/v2/user/current | Get presently logged-in user.
[**getCurrentUser1**](UserApi.md#getCurrentUser1) | **GET** /rest/v1/user/current | Get presently logged-in user.
[**getMatchingUsers**](UserApi.md#getMatchingUsers) | **GET** /rest/v2/user/matches | Get presently logged-in user.
[**getMatchingUsers1**](UserApi.md#getMatchingUsers1) | **GET** /rest/v1/user/matches | Get presently logged-in user.
[**getUser**](UserApi.md#getUser) | **GET** /rest/v2/user/{userId} | Get a user by his ID
[**getUser1**](UserApi.md#getUser1) | **GET** /rest/v1/user/{userId} | Get a user by his ID
[**getUserByEmail**](UserApi.md#getUserByEmail) | **GET** /rest/v2/user/byEmail/{email} | Get a user by his Email/Login
[**getUserByEmail1**](UserApi.md#getUserByEmail1) | **GET** /rest/v1/user/byEmail/{email} | Get a user by his Email/Login
[**listUsers**](UserApi.md#listUsers) | **GET** /rest/v1/user | List users with(out) pagination
[**listUsersBy**](UserApi.md#listUsersBy) | **GET** /rest/v2/user | List users with(out) pagination
[**listUsersInGroup**](UserApi.md#listUsersInGroup) | **GET** /rest/v2/user/inGroup/{groupId} | List users with(out) pagination
[**listUsersInGroup1**](UserApi.md#listUsersInGroup1) | **GET** /rest/v1/user/inGroup/{groupId} | List users with(out) pagination
[**modifyProperties**](UserApi.md#modifyProperties) | **PUT** /rest/v2/user/{userId}/properties | Modify a User property
[**modifyProperties1**](UserApi.md#modifyProperties1) | **PUT** /rest/v1/user/{userId}/properties | Modify a User property
[**modifyUser**](UserApi.md#modifyUser) | **PUT** /rest/v2/user | Modify a user.
[**modifyUser1**](UserApi.md#modifyUser1) | **PUT** /rest/v1/user | Modify a user.
[**modifyUserInGroup**](UserApi.md#modifyUserInGroup) | **PUT** /rest/v2/user/inGroup/{groupId} | Modify a user.
[**modifyUserInGroup1**](UserApi.md#modifyUserInGroup1) | **PUT** /rest/v1/user/inGroup/{groupId} | Modify a user.


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

<a name="assignHealthcareParty1"></a>
# **assignHealthcareParty1**
> UserDto assignHealthcareParty1(healthcarePartyId)

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
    val result : UserDto = apiInstance.assignHealthcareParty1(healthcarePartyId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#assignHealthcareParty1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#assignHealthcareParty1")
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

<a name="checkPassword1"></a>
# **checkPassword1**
> kotlin.Boolean checkPassword1(password)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val password : kotlin.String = password_example // kotlin.String | 
try {
    val result : kotlin.Boolean = apiInstance.checkPassword1(password)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#checkPassword1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#checkPassword1")
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

<a name="createUser1"></a>
# **createUser1**
> UserDto createUser1(userDto)

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
    val result : UserDto = apiInstance.createUser1(userDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#createUser1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#createUser1")
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

<a name="createUserInGroup1"></a>
# **createUserInGroup1**
> UserDto createUserInGroup1(groupId, userDto)

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
    val result : UserDto = apiInstance.createUserInGroup1(groupId, userDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#createUserInGroup1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#createUserInGroup1")
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

<a name="deleteUser1"></a>
# **deleteUser1**
> DocIdentifier deleteUser1(userId)

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
    val result : DocIdentifier = apiInstance.deleteUser1(userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#deleteUser1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#deleteUser1")
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

<a name="deleteUserInGroup1"></a>
# **deleteUserInGroup1**
> kotlin.Any deleteUserInGroup1(groupId, userId)

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
    val result : kotlin.Any = apiInstance.deleteUserInGroup1(groupId, userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#deleteUserInGroup1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#deleteUserInGroup1")
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

<a name="encodePassword1"></a>
# **encodePassword1**
> kotlin.String encodePassword1(password)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val password : kotlin.String = password_example // kotlin.String | 
try {
    val result : kotlin.String = apiInstance.encodePassword1(password)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#encodePassword1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#encodePassword1")
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

<a name="findByHcpartyId1"></a>
# **findByHcpartyId1**
> kotlin.collections.List&lt;kotlin.String&gt; findByHcpartyId1(id)

Get the list of users by healthcare party id

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val id : kotlin.String = id_example // kotlin.String | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.findByHcpartyId1(id)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#findByHcpartyId1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#findByHcpartyId1")
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

<a name="forgottenPassword"></a>
# **forgottenPassword**
> kotlin.Boolean forgottenPassword(email, emailTemplateDto)

Send a forgotten email message to an user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val email : kotlin.String = email_example // kotlin.String | the email of the user 
val emailTemplateDto : EmailTemplateDto =  // EmailTemplateDto | 
try {
    val result : kotlin.Boolean = apiInstance.forgottenPassword(email, emailTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#forgottenPassword")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#forgottenPassword")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **email** | **kotlin.String**| the email of the user  |
 **emailTemplateDto** | [**EmailTemplateDto**](EmailTemplateDto.md)|  |

### Return type

**kotlin.Boolean**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="forgottenPassword1"></a>
# **forgottenPassword1**
> kotlin.Boolean forgottenPassword1(email, emailTemplateDto)

Send a forgotten email message to an user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
val email : kotlin.String = email_example // kotlin.String | the email of the user 
val emailTemplateDto : EmailTemplateDto =  // EmailTemplateDto | 
try {
    val result : kotlin.Boolean = apiInstance.forgottenPassword1(email, emailTemplateDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#forgottenPassword1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#forgottenPassword1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **email** | **kotlin.String**| the email of the user  |
 **emailTemplateDto** | [**EmailTemplateDto**](EmailTemplateDto.md)|  |

### Return type

**kotlin.Boolean**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
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

<a name="getCurrentSession1"></a>
# **getCurrentSession1**
> kotlin.String getCurrentSession1()

Get Currently logged-in user session.

Get current user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
try {
    val result : kotlin.String = apiInstance.getCurrentSession1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getCurrentSession1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getCurrentSession1")
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

<a name="getCurrentUser1"></a>
# **getCurrentUser1**
> UserDto getCurrentUser1()

Get presently logged-in user.

Get current user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
try {
    val result : UserDto = apiInstance.getCurrentUser1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getCurrentUser1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getCurrentUser1")
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

<a name="getMatchingUsers1"></a>
# **getMatchingUsers1**
> kotlin.collections.List&lt;UserGroupDto&gt; getMatchingUsers1()

Get presently logged-in user.

Get current user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = UserApi()
try {
    val result : kotlin.collections.List<UserGroupDto> = apiInstance.getMatchingUsers1()
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getMatchingUsers1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getMatchingUsers1")
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

<a name="getUser1"></a>
# **getUser1**
> UserDto getUser1(userId)

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
    val result : UserDto = apiInstance.getUser1(userId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getUser1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getUser1")
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

<a name="getUserByEmail1"></a>
# **getUserByEmail1**
> UserDto getUserByEmail1(email)

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
    val result : UserDto = apiInstance.getUserByEmail1(email)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#getUserByEmail1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#getUserByEmail1")
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

<a name="listUsers"></a>
# **listUsers**
> PaginatedListUserDto listUsers(startKey, startDocumentId, limit)

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
try {
    val result : PaginatedListUserDto = apiInstance.listUsers(startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#listUsers")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#listUsers")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **startKey** | **kotlin.String**| An user email | [optional]
 **startDocumentId** | **kotlin.String**| An user document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListUserDto**](PaginatedListUserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="listUsersBy"></a>
# **listUsersBy**
> PaginatedListUserDto listUsersBy(startKey, startDocumentId, limit)

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
try {
    val result : PaginatedListUserDto = apiInstance.listUsersBy(startKey, startDocumentId, limit)
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

<a name="listUsersInGroup1"></a>
# **listUsersInGroup1**
> PaginatedListUserDto listUsersInGroup1(groupId, startKey, startDocumentId, limit)

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
    val result : PaginatedListUserDto = apiInstance.listUsersInGroup1(groupId, startKey, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#listUsersInGroup1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#listUsersInGroup1")
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

<a name="modifyProperties1"></a>
# **modifyProperties1**
> UserDto modifyProperties1(userId, propertyStubDto)

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
    val result : UserDto = apiInstance.modifyProperties1(userId, propertyStubDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#modifyProperties1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#modifyProperties1")
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

<a name="modifyUser1"></a>
# **modifyUser1**
> UserDto modifyUser1(userDto)

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
    val result : UserDto = apiInstance.modifyUser1(userDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#modifyUser1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#modifyUser1")
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

<a name="modifyUserInGroup1"></a>
# **modifyUserInGroup1**
> UserDto modifyUserInGroup1(groupId, userDto)

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
    val result : UserDto = apiInstance.modifyUserInGroup1(groupId, userDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling UserApi#modifyUserInGroup1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling UserApi#modifyUserInGroup1")
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

