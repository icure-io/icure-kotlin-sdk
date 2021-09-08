# BekmehrApi

All URIs are relative to *https://kraken.icure.dev*

Method | HTTP request | Description
------------- | ------------- | -------------
[**checkIfSMFPatientsExists**](BekmehrApi.md#checkIfSMFPatientsExists) | **POST** /rest/v2/be_kmehr/smf/{documentId}/checkIfSMFPatientsExists | Check whether patients in SMF already exists in DB
[**checkIfSMFPatientsExists1**](BekmehrApi.md#checkIfSMFPatientsExists1) | **POST** /rest/v1/be_kmehr/smf/{documentId}/checkIfSMFPatientsExists | Check whether patients in SMF already exists in DB
[**generateContactreportExport**](BekmehrApi.md#generateContactreportExport) | **POST** /rest/v2/be_kmehr/contactreport/{patientId}/export/{id} | Get Kmehr contactreport
[**generateContactreportExport1**](BekmehrApi.md#generateContactreportExport1) | **POST** /rest/v1/be_kmehr/contactreport/{patientId}/export/{id} | Get Kmehr contactreport
[**generateDiaryNote**](BekmehrApi.md#generateDiaryNote) | **POST** /rest/v2/be_kmehr/diarynote/{patientId}/export | Generate diarynote
[**generateDiaryNote1**](BekmehrApi.md#generateDiaryNote1) | **POST** /rest/v1/be_kmehr/diarynote/{patientId}/export | Generate diarynote
[**generateLabresultExport**](BekmehrApi.md#generateLabresultExport) | **POST** /rest/v2/be_kmehr/labresult/{patientId}/export/{id} | Get Kmehr labresult
[**generateLabresultExport1**](BekmehrApi.md#generateLabresultExport1) | **POST** /rest/v1/be_kmehr/labresult/{patientId}/export/{id} | Get Kmehr labresult
[**generateMedicationSchemeExport**](BekmehrApi.md#generateMedicationSchemeExport) | **POST** /rest/v2/be_kmehr/medicationscheme/{patientId}/export | Get Medicationscheme export
[**generateMedicationSchemeExport1**](BekmehrApi.md#generateMedicationSchemeExport1) | **POST** /rest/v1/be_kmehr/medicationscheme/{patientId}/export | Get Medicationscheme export
[**generateNoteExport**](BekmehrApi.md#generateNoteExport) | **POST** /rest/v2/be_kmehr/note/{patientId}/export/{id} | Get Kmehr note
[**generateNoteExport1**](BekmehrApi.md#generateNoteExport1) | **POST** /rest/v1/be_kmehr/note/{patientId}/export/{id} | Get Kmehr note
[**generatePatientInfoExport**](BekmehrApi.md#generatePatientInfoExport) | **POST** /rest/v2/be_kmehr/patientinfo/{patientId}/export | Get KMEHR Patient Info export
[**generatePatientInfoExport1**](BekmehrApi.md#generatePatientInfoExport1) | **POST** /rest/v1/be_kmehr/patientinfo/{patientId}/export | Get KMEHR Patient Info export
[**generatePrescriptionExport**](BekmehrApi.md#generatePrescriptionExport) | **POST** /rest/v2/be_kmehr/prescription/{patientId}/export/{id} | Get Kmehr prescription
[**generatePrescriptionExport1**](BekmehrApi.md#generatePrescriptionExport1) | **POST** /rest/v1/be_kmehr/prescription/{patientId}/export/{id} | Get Kmehr prescription
[**generateReportExport**](BekmehrApi.md#generateReportExport) | **POST** /rest/v2/be_kmehr/report/{patientId}/export/{id} | Get Kmehr report
[**generateReportExport1**](BekmehrApi.md#generateReportExport1) | **POST** /rest/v1/be_kmehr/report/{patientId}/export/{id} | Get Kmehr report
[**generateRequestExport**](BekmehrApi.md#generateRequestExport) | **POST** /rest/v2/be_kmehr/request/{patientId}/export/{id} | Get Kmehr request
[**generateRequestExport1**](BekmehrApi.md#generateRequestExport1) | **POST** /rest/v1/be_kmehr/request/{patientId}/export/{id} | Get Kmehr request
[**generateResultExport**](BekmehrApi.md#generateResultExport) | **POST** /rest/v2/be_kmehr/result/{patientId}/export/{id} | Get Kmehr result
[**generateResultExport1**](BekmehrApi.md#generateResultExport1) | **POST** /rest/v1/be_kmehr/result/{patientId}/export/{id} | Get Kmehr result
[**generateSmfExport**](BekmehrApi.md#generateSmfExport) | **POST** /rest/v2/be_kmehr/smf/{patientId}/export | Get SMF (Software Medical File) export
[**generateSmfExport1**](BekmehrApi.md#generateSmfExport1) | **POST** /rest/v1/be_kmehr/smf/{patientId}/export | Get SMF (Software Medical File) export
[**generateSumehr**](BekmehrApi.md#generateSumehr) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/export | Generate sumehr
[**generateSumehr1**](BekmehrApi.md#generateSumehr1) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/export | Generate sumehr
[**generateSumehrV2**](BekmehrApi.md#generateSumehrV2) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/export | Generate sumehr
[**generateSumehrV21**](BekmehrApi.md#generateSumehrV21) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/export | Generate sumehr
[**getSumehrContent**](BekmehrApi.md#getSumehrContent) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/content | Get sumehr elements
[**getSumehrContent1**](BekmehrApi.md#getSumehrContent1) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/content | Get sumehr elements
[**getSumehrMd5**](BekmehrApi.md#getSumehrMd5) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/md5 | Check sumehr signature
[**getSumehrMd51**](BekmehrApi.md#getSumehrMd51) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/md5 | Check sumehr signature
[**getSumehrV2Content**](BekmehrApi.md#getSumehrV2Content) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/content | Get sumehr elements
[**getSumehrV2Content1**](BekmehrApi.md#getSumehrV2Content1) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/content | Get sumehr elements
[**getSumehrV2Md5**](BekmehrApi.md#getSumehrV2Md5) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/md5 | Check sumehr signature
[**getSumehrV2Md51**](BekmehrApi.md#getSumehrV2Md51) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/md5 | Check sumehr signature
[**importMedicationScheme**](BekmehrApi.md#importMedicationScheme) | **POST** /rest/v2/be_kmehr/medicationscheme/{documentId}/import | Import MedicationScheme into patient(s) using existing document
[**importMedicationScheme1**](BekmehrApi.md#importMedicationScheme1) | **POST** /rest/v1/be_kmehr/medicationscheme/{documentId}/import | Import MedicationScheme into patient(s) using existing document
[**importSmf**](BekmehrApi.md#importSmf) | **POST** /rest/v2/be_kmehr/smf/{documentId}/import | Import SMF into patient(s) using existing document
[**importSmf1**](BekmehrApi.md#importSmf1) | **POST** /rest/v1/be_kmehr/smf/{documentId}/import | Import SMF into patient(s) using existing document
[**importSumehr**](BekmehrApi.md#importSumehr) | **POST** /rest/v2/be_kmehr/sumehr/{documentId}/import | Import sumehr into patient(s) using existing document
[**importSumehr1**](BekmehrApi.md#importSumehr1) | **POST** /rest/v1/be_kmehr/sumehr/{documentId}/import | Import sumehr into patient(s) using existing document
[**importSumehrByItemId**](BekmehrApi.md#importSumehrByItemId) | **POST** /rest/v2/be_kmehr/sumehr/{documentId}/importbyitemid | Import sumehr into patient(s) using existing document
[**importSumehrByItemId1**](BekmehrApi.md#importSumehrByItemId1) | **POST** /rest/v1/be_kmehr/sumehr/{documentId}/importbyitemid | Import sumehr into patient(s) using existing document
[**isSumehrV2Valid**](BekmehrApi.md#isSumehrV2Valid) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/valid | Get sumehr validity
[**isSumehrV2Valid1**](BekmehrApi.md#isSumehrV2Valid1) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/valid | Get sumehr validity
[**isSumehrValid**](BekmehrApi.md#isSumehrValid) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/valid | Get sumehr validity
[**isSumehrValid1**](BekmehrApi.md#isSumehrValid1) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/valid | Get sumehr validity
[**validateSumehr**](BekmehrApi.md#validateSumehr) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/validate | Validate sumehr
[**validateSumehr1**](BekmehrApi.md#validateSumehr1) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/validate | Validate sumehr
[**validateSumehrV2**](BekmehrApi.md#validateSumehrV2) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/validate | Validate sumehr
[**validateSumehrV21**](BekmehrApi.md#validateSumehrV21) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/validate | Validate sumehr


<a name="checkIfSMFPatientsExists"></a>
# **checkIfSMFPatientsExists**
> kotlin.collections.List&lt;CheckSMFPatientResult&gt; checkIfSMFPatientsExists(documentId, documentKey, patientId, language, requestBody)

Check whether patients in SMF already exists in DB

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<CheckSMFPatientResult> = apiInstance.checkIfSMFPatientsExists(documentId, documentKey, patientId, language, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#checkIfSMFPatientsExists")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#checkIfSMFPatientsExists")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;CheckSMFPatientResult&gt;**](CheckSMFPatientResult.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="checkIfSMFPatientsExists1"></a>
# **checkIfSMFPatientsExists1**
> kotlin.collections.List&lt;CheckSMFPatientResult&gt; checkIfSMFPatientsExists1(documentId, documentKey, patientId, language, requestBody)

Check whether patients in SMF already exists in DB

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<CheckSMFPatientResult> = apiInstance.checkIfSMFPatientsExists1(documentId, documentKey, patientId, language, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#checkIfSMFPatientsExists1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#checkIfSMFPatientsExists1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;CheckSMFPatientResult&gt;**](CheckSMFPatientResult.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="generateContactreportExport"></a>
# **generateContactreportExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateContactreportExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)

Get Kmehr contactreport

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.ByteArray> =  // kotlin.collections.List<kotlin.ByteArray> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateContactreportExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateContactreportExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateContactreportExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.ByteArray&gt;**](kotlin.ByteArray.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateContactreportExport1"></a>
# **generateContactreportExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateContactreportExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)

Get Kmehr contactreport

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateContactreportExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateContactreportExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateContactreportExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateDiaryNote"></a>
# **generateDiaryNote**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateDiaryNote(patientId, language, diaryNoteExportInfoDto)

Generate diarynote

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val diaryNoteExportInfoDto : DiaryNoteExportInfoDto =  // DiaryNoteExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateDiaryNote(patientId, language, diaryNoteExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateDiaryNote")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateDiaryNote")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **diaryNoteExportInfoDto** | [**DiaryNoteExportInfoDto**](DiaryNoteExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="generateDiaryNote1"></a>
# **generateDiaryNote1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateDiaryNote1(patientId, language, diaryNoteExportInfoDto)

Generate diarynote

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val diaryNoteExportInfoDto : DiaryNoteExportInfoDto =  // DiaryNoteExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateDiaryNote1(patientId, language, diaryNoteExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateDiaryNote1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateDiaryNote1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **diaryNoteExportInfoDto** | [**DiaryNoteExportInfoDto**](DiaryNoteExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="generateLabresultExport"></a>
# **generateLabresultExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateLabresultExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)

Get Kmehr labresult

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.ByteArray> =  // kotlin.collections.List<kotlin.ByteArray> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateLabresultExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateLabresultExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateLabresultExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.ByteArray&gt;**](kotlin.ByteArray.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateLabresultExport1"></a>
# **generateLabresultExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateLabresultExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)

Get Kmehr labresult

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateLabresultExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateLabresultExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateLabresultExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateMedicationSchemeExport"></a>
# **generateMedicationSchemeExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateMedicationSchemeExport(patientId, language, recipientSafe, version, medicationSchemeExportInfoDto)

Get Medicationscheme export

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientSafe : kotlin.String = recipientSafe_example // kotlin.String | 
val version : kotlin.Int = 56 // kotlin.Int | 
val medicationSchemeExportInfoDto : MedicationSchemeExportInfoDto =  // MedicationSchemeExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateMedicationSchemeExport(patientId, language, recipientSafe, version, medicationSchemeExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateMedicationSchemeExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateMedicationSchemeExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **recipientSafe** | **kotlin.String**|  |
 **version** | **kotlin.Int**|  |
 **medicationSchemeExportInfoDto** | [**MedicationSchemeExportInfoDto**](MedicationSchemeExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="generateMedicationSchemeExport1"></a>
# **generateMedicationSchemeExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateMedicationSchemeExport1(patientId, language, recipientSafe, version, medicationSchemeExportInfoDto)

Get Medicationscheme export

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientSafe : kotlin.String = recipientSafe_example // kotlin.String | 
val version : kotlin.Int = 56 // kotlin.Int | 
val medicationSchemeExportInfoDto : MedicationSchemeExportInfoDto =  // MedicationSchemeExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateMedicationSchemeExport1(patientId, language, recipientSafe, version, medicationSchemeExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateMedicationSchemeExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateMedicationSchemeExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **recipientSafe** | **kotlin.String**|  |
 **version** | **kotlin.Int**|  |
 **medicationSchemeExportInfoDto** | [**MedicationSchemeExportInfoDto**](MedicationSchemeExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="generateNoteExport"></a>
# **generateNoteExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateNoteExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)

Get Kmehr note

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.ByteArray> =  // kotlin.collections.List<kotlin.ByteArray> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateNoteExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateNoteExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateNoteExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.ByteArray&gt;**](kotlin.ByteArray.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateNoteExport1"></a>
# **generateNoteExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateNoteExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)

Get Kmehr note

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateNoteExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateNoteExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateNoteExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generatePatientInfoExport"></a>
# **generatePatientInfoExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generatePatientInfoExport(patientId, language)

Get KMEHR Patient Info export

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generatePatientInfoExport(patientId, language)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generatePatientInfoExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generatePatientInfoExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  | [optional]

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

<a name="generatePatientInfoExport1"></a>
# **generatePatientInfoExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generatePatientInfoExport1(patientId, language)

Get KMEHR Patient Info export

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generatePatientInfoExport1(patientId, language)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generatePatientInfoExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generatePatientInfoExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  | [optional]

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/octet-stream

<a name="generatePrescriptionExport"></a>
# **generatePrescriptionExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generatePrescriptionExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)

Get Kmehr prescription

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.ByteArray> =  // kotlin.collections.List<kotlin.ByteArray> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generatePrescriptionExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generatePrescriptionExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generatePrescriptionExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.ByteArray&gt;**](kotlin.ByteArray.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generatePrescriptionExport1"></a>
# **generatePrescriptionExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generatePrescriptionExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)

Get Kmehr prescription

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generatePrescriptionExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generatePrescriptionExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generatePrescriptionExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateReportExport"></a>
# **generateReportExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateReportExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)

Get Kmehr report

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.ByteArray> =  // kotlin.collections.List<kotlin.ByteArray> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateReportExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateReportExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateReportExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.ByteArray&gt;**](kotlin.ByteArray.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateReportExport1"></a>
# **generateReportExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateReportExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)

Get Kmehr report

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateReportExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateReportExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateReportExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateRequestExport"></a>
# **generateRequestExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateRequestExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)

Get Kmehr request

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.ByteArray> =  // kotlin.collections.List<kotlin.ByteArray> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateRequestExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateRequestExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateRequestExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.ByteArray&gt;**](kotlin.ByteArray.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateRequestExport1"></a>
# **generateRequestExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateRequestExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)

Get Kmehr request

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateRequestExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateRequestExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateRequestExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateResultExport"></a>
# **generateResultExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateResultExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)

Get Kmehr result

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val requestBody : kotlin.collections.List<kotlin.ByteArray> =  // kotlin.collections.List<kotlin.ByteArray> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateResultExport(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateResultExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateResultExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **requestBody** | [**kotlin.collections.List&lt;kotlin.ByteArray&gt;**](kotlin.ByteArray.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateResultExport1"></a>
# **generateResultExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateResultExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)

Get Kmehr result

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val id : kotlin.String = id_example // kotlin.String | 
val date : kotlin.Long = 789 // kotlin.Long | 
val language : kotlin.String = language_example // kotlin.String | 
val recipientNihii : kotlin.String = recipientNihii_example // kotlin.String | 
val recipientSsin : kotlin.String = recipientSsin_example // kotlin.String | 
val recipientFirstName : kotlin.String = recipientFirstName_example // kotlin.String | 
val recipientLastName : kotlin.String = recipientLastName_example // kotlin.String | 
val mimeType : kotlin.String = mimeType_example // kotlin.String | 
val body : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = BINARY_DATA_HERE // kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateResultExport1(patientId, id, date, language, recipientNihii, recipientSsin, recipientFirstName, recipientLastName, mimeType, body)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateResultExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateResultExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **id** | **kotlin.String**|  |
 **date** | **kotlin.Long**|  |
 **language** | **kotlin.String**|  |
 **recipientNihii** | **kotlin.String**|  |
 **recipientSsin** | **kotlin.String**|  |
 **recipientFirstName** | **kotlin.String**|  |
 **recipientLastName** | **kotlin.String**|  |
 **mimeType** | **kotlin.String**|  |
 **body** | **kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/octet-stream
 - **Accept**: application/octet-stream

<a name="generateSmfExport"></a>
# **generateSmfExport**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateSmfExport(patientId, language, softwareMedicalFileExportDto)

Get SMF (Software Medical File) export

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val softwareMedicalFileExportDto : SoftwareMedicalFileExportDto =  // SoftwareMedicalFileExportDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateSmfExport(patientId, language, softwareMedicalFileExportDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateSmfExport")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateSmfExport")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **softwareMedicalFileExportDto** | [**SoftwareMedicalFileExportDto**](SoftwareMedicalFileExportDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="generateSmfExport1"></a>
# **generateSmfExport1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateSmfExport1(patientId, language, softwareMedicalFileExportDto)

Get SMF (Software Medical File) export

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val softwareMedicalFileExportDto : SoftwareMedicalFileExportDto =  // SoftwareMedicalFileExportDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateSmfExport1(patientId, language, softwareMedicalFileExportDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateSmfExport1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateSmfExport1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **softwareMedicalFileExportDto** | [**SoftwareMedicalFileExportDto**](SoftwareMedicalFileExportDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="generateSumehr"></a>
# **generateSumehr**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateSumehr(patientId, language, sumehrExportInfoDto)

Generate sumehr

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateSumehr(patientId, language, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateSumehr")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateSumehr")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="generateSumehr1"></a>
# **generateSumehr1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateSumehr1(patientId, language, sumehrExportInfoDto)

Generate sumehr

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateSumehr1(patientId, language, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateSumehr1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateSumehr1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="generateSumehrV2"></a>
# **generateSumehrV2**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateSumehrV2(patientId, language, sumehrExportInfoDto)

Generate sumehr

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateSumehrV2(patientId, language, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateSumehrV2")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateSumehrV2")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="generateSumehrV21"></a>
# **generateSumehrV21**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; generateSumehrV21(patientId, language, sumehrExportInfoDto)

Generate sumehr

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.generateSumehrV21(patientId, language, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#generateSumehrV21")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#generateSumehrV21")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="getSumehrContent"></a>
# **getSumehrContent**
> SumehrContentDto getSumehrContent(patientId, sumehrExportInfoDto)

Get sumehr elements

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : SumehrContentDto = apiInstance.getSumehrContent(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#getSumehrContent")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#getSumehrContent")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**SumehrContentDto**](SumehrContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getSumehrContent1"></a>
# **getSumehrContent1**
> SumehrContentDto getSumehrContent1(patientId, sumehrExportInfoDto)

Get sumehr elements

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : SumehrContentDto = apiInstance.getSumehrContent1(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#getSumehrContent1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#getSumehrContent1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**SumehrContentDto**](SumehrContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getSumehrMd5"></a>
# **getSumehrMd5**
> ContentDto getSumehrMd5(patientId, sumehrExportInfoDto)

Check sumehr signature

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : ContentDto = apiInstance.getSumehrMd5(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#getSumehrMd5")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#getSumehrMd5")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**ContentDto**](ContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getSumehrMd51"></a>
# **getSumehrMd51**
> ContentDto getSumehrMd51(patientId, sumehrExportInfoDto)

Check sumehr signature

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : ContentDto = apiInstance.getSumehrMd51(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#getSumehrMd51")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#getSumehrMd51")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**ContentDto**](ContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getSumehrV2Content"></a>
# **getSumehrV2Content**
> SumehrContentDto getSumehrV2Content(patientId, sumehrExportInfoDto)

Get sumehr elements

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : SumehrContentDto = apiInstance.getSumehrV2Content(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#getSumehrV2Content")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#getSumehrV2Content")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**SumehrContentDto**](SumehrContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getSumehrV2Content1"></a>
# **getSumehrV2Content1**
> SumehrContentDto getSumehrV2Content1(patientId, sumehrExportInfoDto)

Get sumehr elements

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : SumehrContentDto = apiInstance.getSumehrV2Content1(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#getSumehrV2Content1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#getSumehrV2Content1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**SumehrContentDto**](SumehrContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getSumehrV2Md5"></a>
# **getSumehrV2Md5**
> ContentDto getSumehrV2Md5(patientId, sumehrExportInfoDto)

Check sumehr signature

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : ContentDto = apiInstance.getSumehrV2Md5(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#getSumehrV2Md5")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#getSumehrV2Md5")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**ContentDto**](ContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="getSumehrV2Md51"></a>
# **getSumehrV2Md51**
> ContentDto getSumehrV2Md51(patientId, sumehrExportInfoDto)

Check sumehr signature

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : ContentDto = apiInstance.getSumehrV2Md51(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#getSumehrV2Md51")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#getSumehrV2Md51")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**ContentDto**](ContentDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="importMedicationScheme"></a>
# **importMedicationScheme**
> kotlin.collections.List&lt;ImportResultDto&gt; importMedicationScheme(documentId, documentKey, dryRun, patientId, language, requestBody)

Import MedicationScheme into patient(s) using existing document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val dryRun : kotlin.Boolean = true // kotlin.Boolean | Dry run: do not save in database
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<ImportResultDto> = apiInstance.importMedicationScheme(documentId, documentKey, dryRun, patientId, language, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#importMedicationScheme")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#importMedicationScheme")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **dryRun** | **kotlin.Boolean**| Dry run: do not save in database | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;ImportResultDto&gt;**](ImportResultDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="importMedicationScheme1"></a>
# **importMedicationScheme1**
> kotlin.collections.List&lt;ImportResultDto&gt; importMedicationScheme1(documentId, documentKey, dryRun, patientId, language, requestBody)

Import MedicationScheme into patient(s) using existing document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val dryRun : kotlin.Boolean = true // kotlin.Boolean | Dry run: do not save in database
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<ImportResultDto> = apiInstance.importMedicationScheme1(documentId, documentKey, dryRun, patientId, language, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#importMedicationScheme1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#importMedicationScheme1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **dryRun** | **kotlin.Boolean**| Dry run: do not save in database | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;ImportResultDto&gt;**](ImportResultDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="importSmf"></a>
# **importSmf**
> kotlin.collections.List&lt;ImportResultDto&gt; importSmf(documentId, documentKey, patientId, language, dryRun, requestBody)

Import SMF into patient(s) using existing document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val dryRun : kotlin.Boolean = true // kotlin.Boolean | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<ImportResultDto> = apiInstance.importSmf(documentId, documentKey, patientId, language, dryRun, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#importSmf")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#importSmf")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **dryRun** | **kotlin.Boolean**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;ImportResultDto&gt;**](ImportResultDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="importSmf1"></a>
# **importSmf1**
> kotlin.collections.List&lt;ImportResultDto&gt; importSmf1(documentId, documentKey, patientId, language, dryRun, requestBody)

Import SMF into patient(s) using existing document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val dryRun : kotlin.Boolean = true // kotlin.Boolean | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<ImportResultDto> = apiInstance.importSmf1(documentId, documentKey, patientId, language, dryRun, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#importSmf1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#importSmf1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **dryRun** | **kotlin.Boolean**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;ImportResultDto&gt;**](ImportResultDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="importSumehr"></a>
# **importSumehr**
> kotlin.collections.List&lt;ImportResultDto&gt; importSumehr(documentId, documentKey, dryRun, patientId, language, requestBody)

Import sumehr into patient(s) using existing document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val dryRun : kotlin.Boolean = true // kotlin.Boolean | Dry run: do not save in database
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<ImportResultDto> = apiInstance.importSumehr(documentId, documentKey, dryRun, patientId, language, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#importSumehr")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#importSumehr")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **dryRun** | **kotlin.Boolean**| Dry run: do not save in database | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;ImportResultDto&gt;**](ImportResultDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="importSumehr1"></a>
# **importSumehr1**
> kotlin.collections.List&lt;ImportResultDto&gt; importSumehr1(documentId, documentKey, dryRun, patientId, language, requestBody)

Import sumehr into patient(s) using existing document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val dryRun : kotlin.Boolean = true // kotlin.Boolean | Dry run: do not save in database
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<ImportResultDto> = apiInstance.importSumehr1(documentId, documentKey, dryRun, patientId, language, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#importSumehr1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#importSumehr1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **dryRun** | **kotlin.Boolean**| Dry run: do not save in database | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;ImportResultDto&gt;**](ImportResultDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="importSumehrByItemId"></a>
# **importSumehrByItemId**
> kotlin.collections.List&lt;ImportResultDto&gt; importSumehrByItemId(documentId, itemId, documentKey, dryRun, patientId, language, requestBody)

Import sumehr into patient(s) using existing document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val itemId : kotlin.String = itemId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val dryRun : kotlin.Boolean = true // kotlin.Boolean | Dry run: do not save in database
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<ImportResultDto> = apiInstance.importSumehrByItemId(documentId, itemId, documentKey, dryRun, patientId, language, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#importSumehrByItemId")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#importSumehrByItemId")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **itemId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **dryRun** | **kotlin.Boolean**| Dry run: do not save in database | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;ImportResultDto&gt;**](ImportResultDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="importSumehrByItemId1"></a>
# **importSumehrByItemId1**
> kotlin.collections.List&lt;ImportResultDto&gt; importSumehrByItemId1(documentId, itemId, documentKey, dryRun, patientId, language, requestBody)

Import sumehr into patient(s) using existing document

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val documentId : kotlin.String = documentId_example // kotlin.String | 
val itemId : kotlin.String = itemId_example // kotlin.String | 
val documentKey : kotlin.String = documentKey_example // kotlin.String | 
val dryRun : kotlin.Boolean = true // kotlin.Boolean | Dry run: do not save in database
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val requestBody : kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> =  // kotlin.collections.Map<kotlin.String, kotlin.collections.List<ImportMapping>> | 
try {
    val result : kotlin.collections.List<ImportResultDto> = apiInstance.importSumehrByItemId1(documentId, itemId, documentKey, dryRun, patientId, language, requestBody)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#importSumehrByItemId1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#importSumehrByItemId1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **documentId** | **kotlin.String**|  |
 **itemId** | **kotlin.String**|  |
 **documentKey** | **kotlin.String**|  | [optional]
 **dryRun** | **kotlin.Boolean**| Dry run: do not save in database | [optional]
 **patientId** | **kotlin.String**|  | [optional]
 **language** | **kotlin.String**|  | [optional]
 **requestBody** | [**kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;ImportMapping&gt;&gt;**](kotlin.collections.List.md)|  | [optional]

### Return type

[**kotlin.collections.List&lt;ImportResultDto&gt;**](ImportResultDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="isSumehrV2Valid"></a>
# **isSumehrV2Valid**
> SumehrValidityDto isSumehrV2Valid(patientId, sumehrExportInfoDto)

Get sumehr validity

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : SumehrValidityDto = apiInstance.isSumehrV2Valid(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#isSumehrV2Valid")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#isSumehrV2Valid")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**SumehrValidityDto**](SumehrValidityDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="isSumehrV2Valid1"></a>
# **isSumehrV2Valid1**
> SumehrValidityDto isSumehrV2Valid1(patientId, sumehrExportInfoDto)

Get sumehr validity

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : SumehrValidityDto = apiInstance.isSumehrV2Valid1(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#isSumehrV2Valid1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#isSumehrV2Valid1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**SumehrValidityDto**](SumehrValidityDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="isSumehrValid"></a>
# **isSumehrValid**
> SumehrValidityDto isSumehrValid(patientId, sumehrExportInfoDto)

Get sumehr validity

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : SumehrValidityDto = apiInstance.isSumehrValid(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#isSumehrValid")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#isSumehrValid")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**SumehrValidityDto**](SumehrValidityDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="isSumehrValid1"></a>
# **isSumehrValid1**
> SumehrValidityDto isSumehrValid1(patientId, sumehrExportInfoDto)

Get sumehr validity

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : SumehrValidityDto = apiInstance.isSumehrValid1(patientId, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#isSumehrValid1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#isSumehrValid1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**SumehrValidityDto**](SumehrValidityDto.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: */*

<a name="validateSumehr"></a>
# **validateSumehr**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; validateSumehr(patientId, language, sumehrExportInfoDto)

Validate sumehr

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.validateSumehr(patientId, language, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#validateSumehr")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#validateSumehr")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="validateSumehr1"></a>
# **validateSumehr1**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; validateSumehr1(patientId, language, sumehrExportInfoDto)

Validate sumehr

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.validateSumehr1(patientId, language, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#validateSumehr1")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#validateSumehr1")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="validateSumehrV2"></a>
# **validateSumehrV2**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; validateSumehrV2(patientId, language, sumehrExportInfoDto)

Validate sumehr

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.validateSumehrV2(patientId, language, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#validateSumehrV2")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#validateSumehrV2")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

<a name="validateSumehrV21"></a>
# **validateSumehrV21**
> kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt; validateSumehrV21(patientId, language, sumehrExportInfoDto)

Validate sumehr

### Example
```kotlin
// Import classes:
//import io.icure.kraken.client.infrastructure.*
//import io.icure.kraken.client.models.*

val apiInstance = BekmehrApi()
val patientId : kotlin.String = patientId_example // kotlin.String | 
val language : kotlin.String = language_example // kotlin.String | 
val sumehrExportInfoDto : SumehrExportInfoDto =  // SumehrExportInfoDto | 
try {
    val result : kotlinx.coroutines.flow.Flow<java.nio.ByteBuffer> = apiInstance.validateSumehrV21(patientId, language, sumehrExportInfoDto)
    println(result)
} catch (e: ClientException) {
    println("4xx response calling BekmehrApi#validateSumehrV21")
    e.printStackTrace()
} catch (e: ServerException) {
    println("5xx response calling BekmehrApi#validateSumehrV21")
    e.printStackTrace()
}
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patientId** | **kotlin.String**|  |
 **language** | **kotlin.String**|  |
 **sumehrExportInfoDto** | [**SumehrExportInfoDto**](SumehrExportInfoDto.md)|  |

### Return type

[**kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;**](kotlinx.coroutines.flow.Flow&lt;java.nio.ByteBuffer&gt;.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/octet-stream

