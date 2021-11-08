# BemikronoApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**appointmentsByDate**](BemikronoApi.md#appointmentsByDate) | **GET** /rest/v1/be_mikrono/appointments/byDate/{calendarDate} | Get appointments for patient
[**appointmentsByPatient**](BemikronoApi.md#appointmentsByPatient) | **GET** /rest/v1/be_mikrono/appointments/byPatient/{patientId} | Get appointments for patient
[**createAppointmentTypes**](BemikronoApi.md#createAppointmentTypes) | **POST** /rest/v1/be_mikrono/appointmentTypes | 
[**createAppointments**](BemikronoApi.md#createAppointments) | **POST** /rest/v1/be_mikrono/appointments | Create appointments for owner
[**notify**](BemikronoApi.md#notify) | **GET** /rest/v1/be_mikrono/notify/{appointmentId}/{action} | Notify of an appointment change
[**register**](BemikronoApi.md#register) | **PUT** /rest/v1/be_mikrono/user/{userId}/register | Set credentials for provided user
[**sendMessage**](BemikronoApi.md#sendMessage) | **POST** /rest/v1/be_mikrono/sendMessage | Send message using mikrono from logged user
[**setUserCredentials**](BemikronoApi.md#setUserCredentials) | **PUT** /rest/v1/be_mikrono/user/{userId}/credentials | Set credentials for provided user


<a name="appointmentsByDate"></a>
# **appointmentsByDate**
> kotlin.collections.List&lt;AppointmentDto&gt; appointmentsByDate(calendarDate)

Get appointments for patient

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BemikronoApi()
val calendarDate : kotlin.Long = 789 // kotlin.Long | 
try {
    val result : kotlin.collections.List<AppointmentDto> = apiInstance.appointmentsByDate(calendarDate)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BemikronoApi#appointmentsByDate")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BemikronoApi#appointmentsByDate")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **calendarDate** | **kotlin.Long**|  |

### Return type

[**kotlin.collections.List&lt;AppointmentDto&gt;**](AppointmentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="appointmentsByPatient"></a>
# **appointmentsByPatient**
> kotlin.collections.List&lt;AppointmentDto&gt; appointmentsByPatient(patientId, from, to)

Get appointments for patient

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BemikronoApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val from : kotlin.Long = 789 // kotlin.Long | 
val to : kotlin.Long = 789 // kotlin.Long | 
try {
    val result : kotlin.collections.List<AppointmentDto> = apiInstance.appointmentsByPatient(patientId, from, to)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BemikronoApi#appointmentsByPatient")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BemikronoApi#appointmentsByPatient")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **from** | **kotlin.Long**|  | [optional]
 **to** | **kotlin.Long**|  | [optional]

### Return type

[**kotlin.collections.List&lt;AppointmentDto&gt;**](AppointmentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: */*

<a name="createAppointmentTypes"></a>
# **createAppointmentTypes**
> kotlin.collections.List&lt;MikronoAppointmentTypeRestDto&gt; createAppointmentTypes(mikronoAppointmentTypeRestDto)



### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BemikronoApi()
val mikronoAppointmentTypeRestDto : kotlin.collections.List<MikronoAppointmentTypeRestDto> =  // kotlin.collections.List<MikronoAppointmentTypeRestDto> | 
try {
    val result : kotlin.collections.List<MikronoAppointmentTypeRestDto> = apiInstance.createAppointmentTypes(mikronoAppointmentTypeRestDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BemikronoApi#createAppointmentTypes")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BemikronoApi#createAppointmentTypes")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **mikronoAppointmentTypeRestDto** | [**kotlin.collections.List&lt;MikronoAppointmentTypeRestDto&gt;**](MikronoAppointmentTypeRestDto.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;MikronoAppointmentTypeRestDto&gt;**](MikronoAppointmentTypeRestDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="createAppointments"></a>
# **createAppointments**
> kotlin.collections.List&lt;kotlin.String&gt; createAppointments(appointmentImportDto)

Create appointments for owner

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BemikronoApi()
val appointmentImportDto : kotlin.collections.List<AppointmentImportDto> =  // kotlin.collections.List<AppointmentImportDto> | 
try {
    val result : kotlin.collections.List<kotlin.String> = apiInstance.createAppointments(appointmentImportDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BemikronoApi#createAppointments")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BemikronoApi#createAppointments")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appointmentImportDto** | [**kotlin.collections.List&lt;AppointmentImportDto&gt;**](AppointmentImportDto.md)|  |

### Return type

**kotlin.collections.List&lt;kotlin.String&gt;**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="notify"></a>
# **notify**
> notify(appointmentId, action)

Notify of an appointment change

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BemikronoApi()
val appointmentId : kotlin.String = appointmentId_example // kotlin.String | 
val action : kotlin.String = action_example // kotlin.String | 
try {
    apiInstance.notify(appointmentId, action)
} catch (e: ClientException) {
    println("4xx response calling BemikronoApi#notify")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BemikronoApi#notify")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appointmentId** | **kotlin.String**|  |
 **action** | **kotlin.String**|  |

### Return type

null (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: Not defined

<a name="register"></a>
# **register**
> UserDto register(userId, mikronoCredentialsDto)

Set credentials for provided user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BemikronoApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val mikronoCredentialsDto : MikronoCredentialsDto =  // MikronoCredentialsDto | 
try {
    val result : UserDto = apiInstance.register(userId, mikronoCredentialsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BemikronoApi#register")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BemikronoApi#register")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **mikronoCredentialsDto** | [**MikronoCredentialsDto**](MikronoCredentialsDto.md)|  |

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="sendMessage"></a>
# **sendMessage**
> kotlin.Any sendMessage(emailOrSmsMessageDto)

Send message using mikrono from logged user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BemikronoApi()
val emailOrSmsMessageDto : EmailOrSmsMessageDto =  // EmailOrSmsMessageDto | 
try {
    val result : kotlin.Any = apiInstance.sendMessage(emailOrSmsMessageDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BemikronoApi#sendMessage")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BemikronoApi#sendMessage")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **emailOrSmsMessageDto** | [**EmailOrSmsMessageDto**](EmailOrSmsMessageDto.md)|  |

### Return type

[**kotlin.Any**](kotlin.Any.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="setUserCredentials"></a>
# **setUserCredentials**
> UserDto setUserCredentials(userId, mikronoCredentialsDto)

Set credentials for provided user

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BemikronoApi()
val userId : kotlin.String = userId_example // kotlin.String | 
val mikronoCredentialsDto : MikronoCredentialsDto =  // MikronoCredentialsDto | 
try {
    val result : UserDto = apiInstance.setUserCredentials(userId, mikronoCredentialsDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BemikronoApi#setUserCredentials")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BemikronoApi#setUserCredentials")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **userId** | **kotlin.String**|  |
 **mikronoCredentialsDto** | [**MikronoCredentialsDto**](MikronoCredentialsDto.md)|  | [optional]

### Return type

[**UserDto**](UserDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

