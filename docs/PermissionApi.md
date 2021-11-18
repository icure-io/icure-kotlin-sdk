# PermissionApi

All URIs are relative to *http://localhost:16043*

Method | HTTP request | Description
------------- | ------------- | -------------
[**modifyUserPermissions**](PermissionApi.md#modifyUserPermissions) | **PUT** /rest/v2/permissions/{userId} | Add / Revoke permissions to user


<a name="modifyUserPermissions"></a>
# **modifyUserPermissions**
> kotlin.collections.List&lt;PermissionDto&gt; modifyUserPermissions(userId, permissionDto)

Add / Revoke permissions to user

Add a list of granted and revoked permissions to user.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = PermissionApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val permissionDto : PermissionDto =  // PermissionDto | 
try {
    val result : kotlin.collections.List<PermissionDto> = apiInstance.modifyUserPermissions(userId, permissionDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling PermissionApi#modifyUserPermissions")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling PermissionApi#modifyUserPermissions")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **permissionDto** | [**PermissionDto**](PermissionDto.md)|  |

### Return type

[**kotlin.collections.List&lt;PermissionDto&gt;**](PermissionDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

