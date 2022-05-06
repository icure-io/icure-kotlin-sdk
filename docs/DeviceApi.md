# DeviceApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**createDevice**](DeviceApi.md#createDevice) | **POST** /rest/v2/device | Create a device
[**createDeviceInGroup**](DeviceApi.md#createDeviceInGroup) | **POST** /rest/v2/device/inGroup/{groupId} | Create a device
[**createDevices**](DeviceApi.md#createDevices) | **POST** /rest/v2/device/batch | Create devices in bulk
[**createDevices1**](DeviceApi.md#createDevices1) | **POST** /rest/v2/device/bulk | Create devices in bulk
[**deleteDevice**](DeviceApi.md#deleteDevice) | **DELETE** /rest/v2/device/{deviceId} | Delete device.
[**deleteDevices**](DeviceApi.md#deleteDevices) | **POST** /rest/v2/device/delete/batch | Delete devices.
[**deleteDevicesInGroup**](DeviceApi.md#deleteDevicesInGroup) | **DELETE** /rest/v2/device/inGroup/{groupId}/{deviceIds} | Delete a device
[**filterDevicesBy**](DeviceApi.md#filterDevicesBy) | **POST** /rest/v2/device/filter | Filter devices for the current user (HcParty) 
[**getDevice**](DeviceApi.md#getDevice) | **GET** /rest/v2/device/{deviceId} | Get Device
[**getDeviceHcPartyKeysForDelegate**](DeviceApi.md#getDeviceHcPartyKeysForDelegate) | **GET** /rest/v2/device/{deviceId}/keys | Get the HcParty encrypted AES keys indexed by owner
[**getDevices**](DeviceApi.md#getDevices) | **POST** /rest/v2/device/byIds | Get devices by id
[**getDevicesInGroup**](DeviceApi.md#getDevicesInGroup) | **POST** /rest/v2/device/inGroup/{groupId}/byIds | Get devices by their IDs
[**matchDevicesBy**](DeviceApi.md#matchDevicesBy) | **POST** /rest/v2/device/match | Get ids of devices matching the provided filter for the current user (HcParty) 
[**modifyDeviceInGroup**](DeviceApi.md#modifyDeviceInGroup) | **PUT** /rest/v2/device/inGroup/{groupId} | Modify a Device.
[**updateDevice**](DeviceApi.md#updateDevice) | **PUT** /rest/v2/device | Modify a device
[**updateDevices**](DeviceApi.md#updateDevices) | **PUT** /rest/v2/device/batch | Modify devices in bulk
[**updateDevices1**](DeviceApi.md#updateDevices1) | **PUT** /rest/v2/device/bulk | Modify devices in bulk


<a name="createDevice"></a>
# **createDevice**
> DeviceDto createDevice(deviceDto)

Create a device

Name, last name, date of birth, and gender are required. After creation of the device and obtaining the ID, you need to create an initial delegation.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val deviceDto : DeviceDto =  // DeviceDto | 
try {
    val result : DeviceDto = apiInstance.createDevice(deviceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#createDevice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#createDevice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deviceDto** | [**DeviceDto**](DeviceDto.md)|  |

### Return type

[**DeviceDto**](DeviceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createDeviceInGroup"></a>
# **createDeviceInGroup**
> DeviceDto createDeviceInGroup(groupId, deviceDto)

Create a device

One of Name or Last name+First name, Nihii, and Public key are required.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val deviceDto : DeviceDto =  // DeviceDto | 
try {
    val result : DeviceDto = apiInstance.createDeviceInGroup(groupId, deviceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#createDeviceInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#createDeviceInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **deviceDto** | [**DeviceDto**](DeviceDto.md)|  |

### Return type

[**DeviceDto**](DeviceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createDevices"></a>
# **createDevices**
> kotlin.collections.List&lt;IdWithRevDto&gt; createDevices(deviceDto)

Create devices in bulk

Returns the id and _rev of created devices

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val deviceDto : kotlin.collections.List<DeviceDto> =  // kotlin.collections.List<DeviceDto> | 
try {
    val result : kotlin.collections.List<IdWithRevDto> = apiInstance.createDevices(deviceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#createDevices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#createDevices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deviceDto** | [**kotlin.collections.List&lt;DeviceDto&gt;**](DeviceDto.md)|  |

### Return type

[**kotlin.collections.List&lt;IdWithRevDto&gt;**](IdWithRevDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createDevices1"></a>
# **createDevices1**
> kotlin.collections.List&lt;IdWithRevDto&gt; createDevices1(deviceDto)

Create devices in bulk

Returns the id and _rev of created devices

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val deviceDto : kotlin.collections.List<DeviceDto> =  // kotlin.collections.List<DeviceDto> | 
try {
    val result : kotlin.collections.List<IdWithRevDto> = apiInstance.createDevices1(deviceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#createDevices1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#createDevices1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deviceDto** | [**kotlin.collections.List&lt;DeviceDto&gt;**](DeviceDto.md)|  |

### Return type

[**kotlin.collections.List&lt;IdWithRevDto&gt;**](IdWithRevDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="deleteDevice"></a>
# **deleteDevice**
> DocIdentifier deleteDevice(deviceId)

Delete device.

Response contains the id/rev of deleted device.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val deviceId : kotlin.String = deviceId_example // kotlin.String | 
try {
    val result : DocIdentifier = apiInstance.deleteDevice(deviceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#deleteDevice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#deleteDevice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deviceId** | **kotlin.String**|  |

### Return type

[**DocIdentifier**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="deleteDevices"></a>
# **deleteDevices**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteDevices(listOfIdsDto)

Delete devices.

Response is an array containing the id/rev of deleted devices.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteDevices(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#deleteDevices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#deleteDevices")
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

<a name="deleteDevicesInGroup"></a>
# **deleteDevicesInGroup**
> kotlin.collections.List&lt;DocIdentifier&gt; deleteDevicesInGroup(groupId, deviceIds)

Delete a device

Deleting a device. Response is an array containing the id of deleted device.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val deviceIds : kotlin.String = deviceIds_example // kotlin.String | 
try {
    val result : kotlin.collections.List<DocIdentifier> = apiInstance.deleteDevicesInGroup(groupId, deviceIds)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#deleteDevicesInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#deleteDevicesInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **deviceIds** | **kotlin.String**|  |

### Return type

[**kotlin.collections.List&lt;DocIdentifier&gt;**](DocIdentifier.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="filterDevicesBy"></a>
# **filterDevicesBy**
> PaginatedListDeviceDto filterDevicesBy(filterChainDevice, startDocumentId, limit)

Filter devices for the current user (HcParty) 

Returns a list of devices along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val filterChainDevice : FilterChainDevice =  // FilterChainDevice | 
val startDocumentId : kotlin.String = startDocumentId_example // kotlin.String | A device document ID
val limit : kotlin.Int = 56 // kotlin.Int | Number of rows
try {
    val result : PaginatedListDeviceDto = apiInstance.filterDevicesBy(filterChainDevice, startDocumentId, limit)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#filterDevicesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#filterDevicesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterChainDevice** | [**FilterChainDevice**](FilterChainDevice.md)|  |
 **startDocumentId** | **kotlin.String**| A device document ID | [optional]
 **limit** | **kotlin.Int**| Number of rows | [optional]

### Return type

[**PaginatedListDeviceDto**](PaginatedListDeviceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getDevice"></a>
# **getDevice**
> DeviceDto getDevice(deviceId)

Get Device

It gets device administrative data.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val deviceId : kotlin.String = deviceId_example // kotlin.String | 
try {
    val result : DeviceDto = apiInstance.getDevice(deviceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#getDevice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#getDevice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deviceId** | **kotlin.String**|  |

### Return type

[**DeviceDto**](DeviceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getDeviceHcPartyKeysForDelegate"></a>
# **getDeviceHcPartyKeysForDelegate**
> kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt; getDeviceHcPartyKeysForDelegate(deviceId)

Get the HcParty encrypted AES keys indexed by owner

(key, value) of the map is as follows: (ID of the owner of the encrypted AES key, encrypted AES key)

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val deviceId : kotlin.String = deviceId_example // kotlin.String | The deviceId Id for which information is shared
try {
    val result : kotlin.collections.Map<kotlin.String, kotlin.String> = apiInstance.getDeviceHcPartyKeysForDelegate(deviceId)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#getDeviceHcPartyKeysForDelegate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#getDeviceHcPartyKeysForDelegate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deviceId** | **kotlin.String**| The deviceId Id for which information is shared |

### Return type

**kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="getDevices"></a>
# **getDevices**
> kotlin.collections.List&lt;DeviceDto&gt; getDevices(listOfIdsDto)

Get devices by id

It gets device administrative data.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DeviceDto> = apiInstance.getDevices(listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#getDevices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#getDevices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  |

### Return type

[**kotlin.collections.List&lt;DeviceDto&gt;**](DeviceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getDevicesInGroup"></a>
# **getDevicesInGroup**
> kotlin.collections.List&lt;DeviceDto&gt; getDevicesInGroup(groupId, listOfIdsDto)

Get devices by their IDs

General information about the device

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val listOfIdsDto : ListOfIdsDto =  // ListOfIdsDto | 
try {
    val result : kotlin.collections.List<DeviceDto> = apiInstance.getDevicesInGroup(groupId, listOfIdsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#getDevicesInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#getDevicesInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **listOfIdsDto** | [**ListOfIdsDto**](ListOfIdsDto.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;DeviceDto&gt;**](DeviceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="matchDevicesBy"></a>
# **matchDevicesBy**
> kotlin.collections.List&lt;kotlin.String&gt; matchDevicesBy(abstractFilterDtoDevice)

Get ids of devices matching the provided filter for the current user (HcParty) 

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val abstractFilterDtoDevice : AbstractFilterDtoDevice =  // AbstractFilterDtoDevice | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.matchDevicesBy(abstractFilterDtoDevice)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#matchDevicesBy")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#matchDevicesBy")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **abstractFilterDtoDevice** | [**AbstractFilterDtoDevice**](AbstractFilterDtoDevice.md)|  |

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="modifyDeviceInGroup"></a>
# **modifyDeviceInGroup**
> DeviceDto modifyDeviceInGroup(groupId, deviceDto)

Modify a Device.

No particular return value. It&#39;s just a message.

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val groupId : kotlin.String = groupId_example // kotlin.String | 
val deviceDto : DeviceDto =  // DeviceDto | 
try {
    val result : DeviceDto = apiInstance.modifyDeviceInGroup(groupId, deviceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#modifyDeviceInGroup")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#modifyDeviceInGroup")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **groupId** | **kotlin.String**|  |
 **deviceDto** | [**DeviceDto**](DeviceDto.md)|  |

### Return type

[**DeviceDto**](DeviceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="updateDevice"></a>
# **updateDevice**
> DeviceDto updateDevice(deviceDto)

Modify a device

Returns the updated device

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val deviceDto : DeviceDto =  // DeviceDto | 
try {
    val result : DeviceDto = apiInstance.updateDevice(deviceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#updateDevice")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#updateDevice")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deviceDto** | [**DeviceDto**](DeviceDto.md)|  |

### Return type

[**DeviceDto**](DeviceDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="updateDevices"></a>
# **updateDevices**
> kotlin.collections.List&lt;IdWithRevDto&gt; updateDevices(deviceDto)

Modify devices in bulk

Returns the id and _rev of modified devices

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val deviceDto : kotlin.collections.List<DeviceDto> =  // kotlin.collections.List<DeviceDto> | 
try {
    val result : kotlin.collections.List<IdWithRevDto> = apiInstance.updateDevices(deviceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#updateDevices")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#updateDevices")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deviceDto** | [**kotlin.collections.List&lt;DeviceDto&gt;**](DeviceDto.md)|  |

### Return type

[**kotlin.collections.List&lt;IdWithRevDto&gt;**](IdWithRevDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="updateDevices1"></a>
# **updateDevices1**
> kotlin.collections.List&lt;IdWithRevDto&gt; updateDevices1(deviceDto)

Modify devices in bulk

Returns the id and _rev of modified devices

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = DeviceApi()
val deviceDto : kotlin.collections.List<DeviceDto> =  // kotlin.collections.List<DeviceDto> | 
try {
    val result : kotlin.collections.List<IdWithRevDto> = apiInstance.updateDevices1(deviceDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling DeviceApi#updateDevices1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling DeviceApi#updateDevices1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **deviceDto** | [**kotlin.collections.List&lt;DeviceDto&gt;**](DeviceDto.md)|  |

### Return type

[**kotlin.collections.List&lt;IdWithRevDto&gt;**](IdWithRevDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

