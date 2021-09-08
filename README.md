# io.icure.kraken.client - Kotlin client library for OpenAPI definition

## Requires

* Kotlin 1.4.30
* Gradle 6.8.3

## Build

First, create the gradle wrapper script:

```
gradle wrapper
```

Then, run:

```
./gradlew check assemble
```

This runs all tests and packages the library.

## Features/Implementation Notes

* Supports JSON inputs/outputs, File inputs, and Form inputs.
* Supports collection formats for query parameters: csv, tsv, ssv, pipes.
* Some Kotlin and Java types are fully qualified to avoid conflicts with types defined in OpenAPI definitions.
* Implementation of ApiClient is intended to reduce method counts, specifically to benefit Android targets.

<a name="documentation-for-api-endpoints"></a>
## Documentation for API Endpoints

All URIs are relative to *https://kraken.icure.dev*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*AccesslogApi* | [**createAccessLog**](docs/AccesslogApi.md#createaccesslog) | **POST** /rest/v2/accesslog | Creates an access log
*AccesslogApi* | [**createAccessLog1**](docs/AccesslogApi.md#createaccesslog1) | **POST** /rest/v1/accesslog | Create an access log
*AccesslogApi* | [**deleteAccessLog**](docs/AccesslogApi.md#deleteaccesslog) | **DELETE** /rest/v1/accesslog/{accessLogIds} | Delete access logs by batch
*AccesslogApi* | [**deleteAccessLogs**](docs/AccesslogApi.md#deleteaccesslogs) | **POST** /rest/v2/accesslog/delete/batch | Deletes an access log
*AccesslogApi* | [**findAccessLogsBy**](docs/AccesslogApi.md#findaccesslogsby) | **GET** /rest/v2/accesslog | Get Paginated List of Access logs
*AccesslogApi* | [**findAccessLogsByHCPartyPatientForeignKeys**](docs/AccesslogApi.md#findaccesslogsbyhcpartypatientforeignkeys) | **GET** /rest/v1/accesslog/byHcPartySecretForeignKeys | List access logs found by Healthcare Party and secret foreign keyelementIds.
*AccesslogApi* | [**findAccessLogsByUserAfterDate**](docs/AccesslogApi.md#findaccesslogsbyuserafterdate) | **GET** /rest/v2/accesslog/byUser | Get Paginated List of Access logs by user after date
*AccesslogApi* | [**findByUserAfterDate**](docs/AccesslogApi.md#findbyuserafterdate) | **GET** /rest/v1/accesslog/byUser | Get paginated list of Access Logs
*AccesslogApi* | [**getAccessLog**](docs/AccesslogApi.md#getaccesslog) | **GET** /rest/v2/accesslog/{accessLogId} | Gets an access log
*AccesslogApi* | [**getAccessLog1**](docs/AccesslogApi.md#getaccesslog1) | **GET** /rest/v1/accesslog/{accessLogId} | Get an access log
*AccesslogApi* | [**listAccessLogs**](docs/AccesslogApi.md#listaccesslogs) | **GET** /rest/v1/accesslog | Get paginated list of Access Logs
*AccesslogApi* | [**listAccessLogsByHCPartyAndPatientForeignKeys**](docs/AccesslogApi.md#listaccesslogsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/accesslog/byHcPartySecretForeignKeys | List access logs found By Healthcare Party and secret foreign keyelementIds.
*AccesslogApi* | [**modifyAccessLog**](docs/AccesslogApi.md#modifyaccesslog) | **PUT** /rest/v2/accesslog | Modifies an access log
*AccesslogApi* | [**modifyAccessLog1**](docs/AccesslogApi.md#modifyaccesslog1) | **PUT** /rest/v1/accesslog | Modifies an access log
*AgendaApi* | [**createAgenda**](docs/AgendaApi.md#createagenda) | **POST** /rest/v2/agenda | Creates a agenda
*AgendaApi* | [**createAgenda1**](docs/AgendaApi.md#createagenda1) | **POST** /rest/v1/agenda | Creates a agenda
*AgendaApi* | [**deleteAgenda**](docs/AgendaApi.md#deleteagenda) | **DELETE** /rest/v1/agenda/{agendaIds} | Delete agendas by id
*AgendaApi* | [**deleteAgendas**](docs/AgendaApi.md#deleteagendas) | **POST** /rest/v2/agenda/delete/batch | Deletes agendas
*AgendaApi* | [**getAgenda**](docs/AgendaApi.md#getagenda) | **GET** /rest/v2/agenda/{agendaId} | Gets an agenda
*AgendaApi* | [**getAgenda1**](docs/AgendaApi.md#getagenda1) | **GET** /rest/v1/agenda/{agendaId} | Gets an agenda
*AgendaApi* | [**getAgendas**](docs/AgendaApi.md#getagendas) | **GET** /rest/v2/agenda | Gets all agendas
*AgendaApi* | [**getAgendas1**](docs/AgendaApi.md#getagendas1) | **GET** /rest/v1/agenda | Gets all agendas
*AgendaApi* | [**getAgendasForUser**](docs/AgendaApi.md#getagendasforuser) | **GET** /rest/v2/agenda/byUser | Gets all agendas for user
*AgendaApi* | [**getAgendasForUser1**](docs/AgendaApi.md#getagendasforuser1) | **GET** /rest/v1/agenda/byUser | Gets all agendas for user
*AgendaApi* | [**getReadableAgendasForUser**](docs/AgendaApi.md#getreadableagendasforuser) | **GET** /rest/v2/agenda/readableForUser | Gets readable agendas for user
*AgendaApi* | [**getReadableAgendasForUser1**](docs/AgendaApi.md#getreadableagendasforuser1) | **GET** /rest/v1/agenda/readableForUser | Gets readable agendas for user
*AgendaApi* | [**modifyAgenda**](docs/AgendaApi.md#modifyagenda) | **PUT** /rest/v2/agenda | Modifies an agenda
*AgendaApi* | [**modifyAgenda1**](docs/AgendaApi.md#modifyagenda1) | **PUT** /rest/v1/agenda | Modifies an agenda
*ApplicationsettingsApi* | [**getApplicationSettings**](docs/ApplicationsettingsApi.md#getapplicationsettings) | **GET** /rest/v2/appsettings | Gets all application settings
*ApplicationsettingsApi* | [**getApplicationSettings1**](docs/ApplicationsettingsApi.md#getapplicationsettings1) | **GET** /rest/v1/appsettings | Gets all application settings
*ArticleApi* | [**createArticle**](docs/ArticleApi.md#createarticle) | **POST** /rest/v2/article | Creates a article
*ArticleApi* | [**createArticle1**](docs/ArticleApi.md#createarticle1) | **POST** /rest/v1/article | Creates a article
*ArticleApi* | [**deleteArticle**](docs/ArticleApi.md#deletearticle) | **DELETE** /rest/v1/article/{articleIds} | Deletes an article
*ArticleApi* | [**deleteArticles**](docs/ArticleApi.md#deletearticles) | **POST** /rest/v2/article/delete/batch | Deletes articles
*ArticleApi* | [**getArticle**](docs/ArticleApi.md#getarticle) | **GET** /rest/v2/article/{articleId} | Gets an article
*ArticleApi* | [**getArticle1**](docs/ArticleApi.md#getarticle1) | **GET** /rest/v1/article/{articleId} | Gets an article
*ArticleApi* | [**getArticles**](docs/ArticleApi.md#getarticles) | **GET** /rest/v2/article | Gets all articles
*ArticleApi* | [**getArticles1**](docs/ArticleApi.md#getarticles1) | **GET** /rest/v1/article | Gets all articles
*ArticleApi* | [**modifyArticle**](docs/ArticleApi.md#modifyarticle) | **PUT** /rest/v2/article | Modifies an article
*ArticleApi* | [**modifyArticle1**](docs/ArticleApi.md#modifyarticle1) | **PUT** /rest/v1/article | Modifies an article
*AuthApi* | [**login**](docs/AuthApi.md#login) | **POST** /rest/v2/auth/login | login
*AuthApi* | [**login1**](docs/AuthApi.md#login1) | **POST** /rest/v1/auth/login | login
*AuthApi* | [**logout**](docs/AuthApi.md#logout) | **GET** /rest/v2/auth/logout | logout
*AuthApi* | [**logout1**](docs/AuthApi.md#logout1) | **GET** /rest/v1/auth/logout | logout
*AuthApi* | [**logoutPost**](docs/AuthApi.md#logoutpost) | **POST** /rest/v2/auth/logout | logout
*AuthApi* | [**logoutPost1**](docs/AuthApi.md#logoutpost1) | **POST** /rest/v1/auth/logout | logout
*AuthApi* | [**token**](docs/AuthApi.md#token) | **GET** /rest/v2/auth/token/{method}/{path} | token
*AuthApi* | [**token1**](docs/AuthApi.md#token1) | **GET** /rest/v1/auth/token/{method}/{path} | token
*BeefactApi* | [**createBatchAndMessage**](docs/BeefactApi.md#createbatchandmessage) | **POST** /rest/v2/be_efact/{insuranceId}/{newMessageId}/{numericalRef} | create batch and message
*BeefactApi* | [**createBatchAndMessage1**](docs/BeefactApi.md#createbatchandmessage1) | **POST** /rest/v1/be_efact/{insuranceId}/{newMessageId}/{numericalRef} | create batch and message
*BekmehrApi* | [**checkIfSMFPatientsExists**](docs/BekmehrApi.md#checkifsmfpatientsexists) | **POST** /rest/v2/be_kmehr/smf/{documentId}/checkIfSMFPatientsExists | Check whether patients in SMF already exists in DB
*BekmehrApi* | [**checkIfSMFPatientsExists1**](docs/BekmehrApi.md#checkifsmfpatientsexists1) | **POST** /rest/v1/be_kmehr/smf/{documentId}/checkIfSMFPatientsExists | Check whether patients in SMF already exists in DB
*BekmehrApi* | [**generateContactreportExport**](docs/BekmehrApi.md#generatecontactreportexport) | **POST** /rest/v2/be_kmehr/contactreport/{patientId}/export/{id} | Get Kmehr contactreport
*BekmehrApi* | [**generateContactreportExport1**](docs/BekmehrApi.md#generatecontactreportexport1) | **POST** /rest/v1/be_kmehr/contactreport/{patientId}/export/{id} | Get Kmehr contactreport
*BekmehrApi* | [**generateDiaryNote**](docs/BekmehrApi.md#generatediarynote) | **POST** /rest/v2/be_kmehr/diarynote/{patientId}/export | Generate diarynote
*BekmehrApi* | [**generateDiaryNote1**](docs/BekmehrApi.md#generatediarynote1) | **POST** /rest/v1/be_kmehr/diarynote/{patientId}/export | Generate diarynote
*BekmehrApi* | [**generateLabresultExport**](docs/BekmehrApi.md#generatelabresultexport) | **POST** /rest/v2/be_kmehr/labresult/{patientId}/export/{id} | Get Kmehr labresult
*BekmehrApi* | [**generateLabresultExport1**](docs/BekmehrApi.md#generatelabresultexport1) | **POST** /rest/v1/be_kmehr/labresult/{patientId}/export/{id} | Get Kmehr labresult
*BekmehrApi* | [**generateMedicationSchemeExport**](docs/BekmehrApi.md#generatemedicationschemeexport) | **POST** /rest/v2/be_kmehr/medicationscheme/{patientId}/export | Get Medicationscheme export
*BekmehrApi* | [**generateMedicationSchemeExport1**](docs/BekmehrApi.md#generatemedicationschemeexport1) | **POST** /rest/v1/be_kmehr/medicationscheme/{patientId}/export | Get Medicationscheme export
*BekmehrApi* | [**generateNoteExport**](docs/BekmehrApi.md#generatenoteexport) | **POST** /rest/v2/be_kmehr/note/{patientId}/export/{id} | Get Kmehr note
*BekmehrApi* | [**generateNoteExport1**](docs/BekmehrApi.md#generatenoteexport1) | **POST** /rest/v1/be_kmehr/note/{patientId}/export/{id} | Get Kmehr note
*BekmehrApi* | [**generatePatientInfoExport**](docs/BekmehrApi.md#generatepatientinfoexport) | **POST** /rest/v2/be_kmehr/patientinfo/{patientId}/export | Get KMEHR Patient Info export
*BekmehrApi* | [**generatePatientInfoExport1**](docs/BekmehrApi.md#generatepatientinfoexport1) | **POST** /rest/v1/be_kmehr/patientinfo/{patientId}/export | Get KMEHR Patient Info export
*BekmehrApi* | [**generatePrescriptionExport**](docs/BekmehrApi.md#generateprescriptionexport) | **POST** /rest/v2/be_kmehr/prescription/{patientId}/export/{id} | Get Kmehr prescription
*BekmehrApi* | [**generatePrescriptionExport1**](docs/BekmehrApi.md#generateprescriptionexport1) | **POST** /rest/v1/be_kmehr/prescription/{patientId}/export/{id} | Get Kmehr prescription
*BekmehrApi* | [**generateReportExport**](docs/BekmehrApi.md#generatereportexport) | **POST** /rest/v2/be_kmehr/report/{patientId}/export/{id} | Get Kmehr report
*BekmehrApi* | [**generateReportExport1**](docs/BekmehrApi.md#generatereportexport1) | **POST** /rest/v1/be_kmehr/report/{patientId}/export/{id} | Get Kmehr report
*BekmehrApi* | [**generateRequestExport**](docs/BekmehrApi.md#generaterequestexport) | **POST** /rest/v2/be_kmehr/request/{patientId}/export/{id} | Get Kmehr request
*BekmehrApi* | [**generateRequestExport1**](docs/BekmehrApi.md#generaterequestexport1) | **POST** /rest/v1/be_kmehr/request/{patientId}/export/{id} | Get Kmehr request
*BekmehrApi* | [**generateResultExport**](docs/BekmehrApi.md#generateresultexport) | **POST** /rest/v2/be_kmehr/result/{patientId}/export/{id} | Get Kmehr result
*BekmehrApi* | [**generateResultExport1**](docs/BekmehrApi.md#generateresultexport1) | **POST** /rest/v1/be_kmehr/result/{patientId}/export/{id} | Get Kmehr result
*BekmehrApi* | [**generateSmfExport**](docs/BekmehrApi.md#generatesmfexport) | **POST** /rest/v2/be_kmehr/smf/{patientId}/export | Get SMF (Software Medical File) export
*BekmehrApi* | [**generateSmfExport1**](docs/BekmehrApi.md#generatesmfexport1) | **POST** /rest/v1/be_kmehr/smf/{patientId}/export | Get SMF (Software Medical File) export
*BekmehrApi* | [**generateSumehr**](docs/BekmehrApi.md#generatesumehr) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/export | Generate sumehr
*BekmehrApi* | [**generateSumehr1**](docs/BekmehrApi.md#generatesumehr1) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/export | Generate sumehr
*BekmehrApi* | [**generateSumehrV2**](docs/BekmehrApi.md#generatesumehrv2) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/export | Generate sumehr
*BekmehrApi* | [**generateSumehrV21**](docs/BekmehrApi.md#generatesumehrv21) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/export | Generate sumehr
*BekmehrApi* | [**getSumehrContent**](docs/BekmehrApi.md#getsumehrcontent) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/content | Get sumehr elements
*BekmehrApi* | [**getSumehrContent1**](docs/BekmehrApi.md#getsumehrcontent1) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/content | Get sumehr elements
*BekmehrApi* | [**getSumehrMd5**](docs/BekmehrApi.md#getsumehrmd5) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/md5 | Check sumehr signature
*BekmehrApi* | [**getSumehrMd51**](docs/BekmehrApi.md#getsumehrmd51) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/md5 | Check sumehr signature
*BekmehrApi* | [**getSumehrV2Content**](docs/BekmehrApi.md#getsumehrv2content) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/content | Get sumehr elements
*BekmehrApi* | [**getSumehrV2Content1**](docs/BekmehrApi.md#getsumehrv2content1) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/content | Get sumehr elements
*BekmehrApi* | [**getSumehrV2Md5**](docs/BekmehrApi.md#getsumehrv2md5) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/md5 | Check sumehr signature
*BekmehrApi* | [**getSumehrV2Md51**](docs/BekmehrApi.md#getsumehrv2md51) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/md5 | Check sumehr signature
*BekmehrApi* | [**importMedicationScheme**](docs/BekmehrApi.md#importmedicationscheme) | **POST** /rest/v2/be_kmehr/medicationscheme/{documentId}/import | Import MedicationScheme into patient(s) using existing document
*BekmehrApi* | [**importMedicationScheme1**](docs/BekmehrApi.md#importmedicationscheme1) | **POST** /rest/v1/be_kmehr/medicationscheme/{documentId}/import | Import MedicationScheme into patient(s) using existing document
*BekmehrApi* | [**importSmf**](docs/BekmehrApi.md#importsmf) | **POST** /rest/v2/be_kmehr/smf/{documentId}/import | Import SMF into patient(s) using existing document
*BekmehrApi* | [**importSmf1**](docs/BekmehrApi.md#importsmf1) | **POST** /rest/v1/be_kmehr/smf/{documentId}/import | Import SMF into patient(s) using existing document
*BekmehrApi* | [**importSumehr**](docs/BekmehrApi.md#importsumehr) | **POST** /rest/v2/be_kmehr/sumehr/{documentId}/import | Import sumehr into patient(s) using existing document
*BekmehrApi* | [**importSumehr1**](docs/BekmehrApi.md#importsumehr1) | **POST** /rest/v1/be_kmehr/sumehr/{documentId}/import | Import sumehr into patient(s) using existing document
*BekmehrApi* | [**importSumehrByItemId**](docs/BekmehrApi.md#importsumehrbyitemid) | **POST** /rest/v2/be_kmehr/sumehr/{documentId}/importbyitemid | Import sumehr into patient(s) using existing document
*BekmehrApi* | [**importSumehrByItemId1**](docs/BekmehrApi.md#importsumehrbyitemid1) | **POST** /rest/v1/be_kmehr/sumehr/{documentId}/importbyitemid | Import sumehr into patient(s) using existing document
*BekmehrApi* | [**isSumehrV2Valid**](docs/BekmehrApi.md#issumehrv2valid) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/valid | Get sumehr validity
*BekmehrApi* | [**isSumehrV2Valid1**](docs/BekmehrApi.md#issumehrv2valid1) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/valid | Get sumehr validity
*BekmehrApi* | [**isSumehrValid**](docs/BekmehrApi.md#issumehrvalid) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/valid | Get sumehr validity
*BekmehrApi* | [**isSumehrValid1**](docs/BekmehrApi.md#issumehrvalid1) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/valid | Get sumehr validity
*BekmehrApi* | [**validateSumehr**](docs/BekmehrApi.md#validatesumehr) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/validate | Validate sumehr
*BekmehrApi* | [**validateSumehr1**](docs/BekmehrApi.md#validatesumehr1) | **POST** /rest/v1/be_kmehr/sumehr/{patientId}/validate | Validate sumehr
*BekmehrApi* | [**validateSumehrV2**](docs/BekmehrApi.md#validatesumehrv2) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/validate | Validate sumehr
*BekmehrApi* | [**validateSumehrV21**](docs/BekmehrApi.md#validatesumehrv21) | **POST** /rest/v1/be_kmehr/sumehrv2/{patientId}/validate | Validate sumehr
*BemikronoApi* | [**appointmentsByDate**](docs/BemikronoApi.md#appointmentsbydate) | **GET** /rest/v1/be_mikrono/appointments/byDate/{calendarDate} | Get appointments for patient
*BemikronoApi* | [**appointmentsByPatient**](docs/BemikronoApi.md#appointmentsbypatient) | **GET** /rest/v1/be_mikrono/appointments/byPatient/{patientId} | Get appointments for patient
*BemikronoApi* | [**createAppointmentTypes**](docs/BemikronoApi.md#createappointmenttypes) | **POST** /rest/v1/be_mikrono/appointmentTypes | 
*BemikronoApi* | [**createAppointments**](docs/BemikronoApi.md#createappointments) | **POST** /rest/v1/be_mikrono/appointments | Create appointments for owner
*BemikronoApi* | [**notify**](docs/BemikronoApi.md#notify) | **GET** /rest/v1/be_mikrono/notify/{appointmentId}/{action} | Notify of an appointment change
*BemikronoApi* | [**register**](docs/BemikronoApi.md#register) | **PUT** /rest/v1/be_mikrono/user/{userId}/register | Set credentials for provided user
*BemikronoApi* | [**sendMessage**](docs/BemikronoApi.md#sendmessage) | **POST** /rest/v1/be_mikrono/sendMessage | Send message using mikrono from logged user
*BemikronoApi* | [**setUserCredentials**](docs/BemikronoApi.md#setusercredentials) | **PUT** /rest/v1/be_mikrono/user/{userId}/credentials | Set credentials for provided user
*BeresultexportApi* | [**exportHealthOne**](docs/BeresultexportApi.md#exporthealthone) | **POST** /rest/v2/be_result_export/hl1/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
*BeresultexportApi* | [**exportHealthOne1**](docs/BeresultexportApi.md#exporthealthone1) | **POST** /rest/v1/be_result_export/hl1/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
*BeresultexportApi* | [**exportKmehrReport**](docs/BeresultexportApi.md#exportkmehrreport) | **POST** /rest/v2/be_result_export/kmehrreport/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
*BeresultexportApi* | [**exportKmehrReport1**](docs/BeresultexportApi.md#exportkmehrreport1) | **POST** /rest/v1/be_result_export/kmehrreport/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
*BeresultexportApi* | [**exportMedidoc**](docs/BeresultexportApi.md#exportmedidoc) | **POST** /rest/v2/be_result_export/medidoc/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
*BeresultexportApi* | [**exportMedidoc1**](docs/BeresultexportApi.md#exportmedidoc1) | **POST** /rest/v1/be_result_export/medidoc/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
*BeresultimportApi* | [**canHandle**](docs/BeresultimportApi.md#canhandle) | **GET** /rest/v2/be_result_import/canhandle/{id} | Can we handle this document
*BeresultimportApi* | [**canHandle1**](docs/BeresultimportApi.md#canhandle1) | **GET** /rest/v1/be_result_import/canhandle/{id} | Can we handle this document
*BeresultimportApi* | [**doImport**](docs/BeresultimportApi.md#doimport) | **GET** /rest/v2/be_result_import/import/{documentId}/{hcpId}/{language} | import document
*BeresultimportApi* | [**doImport1**](docs/BeresultimportApi.md#doimport1) | **GET** /rest/v1/be_result_import/import/{documentId}/{hcpId}/{language} | import document
*BeresultimportApi* | [**getInfos**](docs/BeresultimportApi.md#getinfos) | **GET** /rest/v2/be_result_import/infos/{id} | Extract general infos from document
*BeresultimportApi* | [**getInfos1**](docs/BeresultimportApi.md#getinfos1) | **GET** /rest/v1/be_result_import/infos/{id} | Extract general infos from document
*Besamv2Api* | [**findAmpsByDmppCode**](docs/Besamv2Api.md#findampsbydmppcode) | **GET** /rest/v2/be_samv2/amp/byDmppCode/{dmppCode} | Finding AMPs by dmpp code
*Besamv2Api* | [**findAmpsByDmppCode1**](docs/Besamv2Api.md#findampsbydmppcode1) | **GET** /rest/v1/be_samv2/amp/byDmppCode/{dmppCode} | Finding AMPs by dmpp code
*Besamv2Api* | [**findPaginatedAmpsByAtc**](docs/Besamv2Api.md#findpaginatedampsbyatc) | **GET** /rest/v2/be_samv2/vmp/byAtc/{atcCode} | Finding AMPs by atc code with pagination.
*Besamv2Api* | [**findPaginatedAmpsByAtc1**](docs/Besamv2Api.md#findpaginatedampsbyatc1) | **GET** /rest/v1/be_samv2/vmp/byAtc/{atcCode} | Finding AMPs by atc code with pagination.
*Besamv2Api* | [**findPaginatedAmpsByGroupCode**](docs/Besamv2Api.md#findpaginatedampsbygroupcode) | **GET** /rest/v2/be_samv2/amp/byGroupCode/{vmpgCode} | Finding AMPs by group with pagination.
*Besamv2Api* | [**findPaginatedAmpsByGroupCode1**](docs/Besamv2Api.md#findpaginatedampsbygroupcode1) | **GET** /rest/v1/be_samv2/amp/byGroupCode/{vmpgCode} | Finding AMPs by group with pagination.
*Besamv2Api* | [**findPaginatedAmpsByGroupId**](docs/Besamv2Api.md#findpaginatedampsbygroupid) | **GET** /rest/v2/be_samv2/amp/byGroupId/{vmpgId} | Finding AMPs by group with pagination.
*Besamv2Api* | [**findPaginatedAmpsByGroupId1**](docs/Besamv2Api.md#findpaginatedampsbygroupid1) | **GET** /rest/v1/be_samv2/amp/byGroupId/{vmpgId} | Finding AMPs by group with pagination.
*Besamv2Api* | [**findPaginatedAmpsByLabel**](docs/Besamv2Api.md#findpaginatedampsbylabel) | **GET** /rest/v2/be_samv2/amp | Finding AMPs by label with pagination.
*Besamv2Api* | [**findPaginatedAmpsByLabel1**](docs/Besamv2Api.md#findpaginatedampsbylabel1) | **GET** /rest/v1/be_samv2/amp | Finding AMPs by label with pagination.
*Besamv2Api* | [**findPaginatedAmpsByVmpCode**](docs/Besamv2Api.md#findpaginatedampsbyvmpcode) | **GET** /rest/v2/be_samv2/amp/byVmpCode/{vmpCode} | Finding AMPs by vmp code with pagination.
*Besamv2Api* | [**findPaginatedAmpsByVmpCode1**](docs/Besamv2Api.md#findpaginatedampsbyvmpcode1) | **GET** /rest/v1/be_samv2/amp/byVmpCode/{vmpCode} | Finding AMPs by vmp code with pagination.
*Besamv2Api* | [**findPaginatedAmpsByVmpId**](docs/Besamv2Api.md#findpaginatedampsbyvmpid) | **GET** /rest/v2/be_samv2/amp/byVmpId/{vmpId} | Finding AMPs by vmp id with pagination.
*Besamv2Api* | [**findPaginatedAmpsByVmpId1**](docs/Besamv2Api.md#findpaginatedampsbyvmpid1) | **GET** /rest/v1/be_samv2/amp/byVmpId/{vmpId} | Finding AMPs by vmp id with pagination.
*Besamv2Api* | [**findPaginatedNmpsByLabel**](docs/Besamv2Api.md#findpaginatednmpsbylabel) | **GET** /rest/v2/be_samv2/nmp | Finding NMPs by label with pagination.
*Besamv2Api* | [**findPaginatedNmpsByLabel1**](docs/Besamv2Api.md#findpaginatednmpsbylabel1) | **GET** /rest/v1/be_samv2/nmp | Finding NMPs by label with pagination.
*Besamv2Api* | [**findPaginatedVmpGroupsByLabel**](docs/Besamv2Api.md#findpaginatedvmpgroupsbylabel) | **GET** /rest/v2/be_samv2/vmpgroup | Finding VMP groups by language label with pagination.
*Besamv2Api* | [**findPaginatedVmpGroupsByLabel1**](docs/Besamv2Api.md#findpaginatedvmpgroupsbylabel1) | **GET** /rest/v1/be_samv2/vmpgroup | Finding VMP groups by language label with pagination.
*Besamv2Api* | [**findPaginatedVmpGroupsByVmpGroupCode**](docs/Besamv2Api.md#findpaginatedvmpgroupsbyvmpgroupcode) | **GET** /rest/v2/be_samv2/vmpgroup/byGroupCode/{vmpgCode} | Finding VMP groups by cmpgCode with pagination.
*Besamv2Api* | [**findPaginatedVmpGroupsByVmpGroupCode1**](docs/Besamv2Api.md#findpaginatedvmpgroupsbyvmpgroupcode1) | **GET** /rest/v1/be_samv2/vmpgroup/byGroupCode/{vmpgCode} | Finding VMP groups by cmpgCode with pagination.
*Besamv2Api* | [**findPaginatedVmpsByGroupCode**](docs/Besamv2Api.md#findpaginatedvmpsbygroupcode) | **GET** /rest/v2/be_samv2/vmp/byGroupCode/{vmpgCode} | Finding VMPs by group with pagination.
*Besamv2Api* | [**findPaginatedVmpsByGroupCode1**](docs/Besamv2Api.md#findpaginatedvmpsbygroupcode1) | **GET** /rest/v1/be_samv2/vmp/byGroupCode/{vmpgCode} | Finding VMPs by group with pagination.
*Besamv2Api* | [**findPaginatedVmpsByGroupId**](docs/Besamv2Api.md#findpaginatedvmpsbygroupid) | **GET** /rest/v2/be_samv2/vmp/byGroupId/{vmpgId} | Finding VMPs by group with pagination.
*Besamv2Api* | [**findPaginatedVmpsByGroupId1**](docs/Besamv2Api.md#findpaginatedvmpsbygroupid1) | **GET** /rest/v1/be_samv2/vmp/byGroupId/{vmpgId} | Finding VMPs by group with pagination.
*Besamv2Api* | [**findPaginatedVmpsByLabel**](docs/Besamv2Api.md#findpaginatedvmpsbylabel) | **GET** /rest/v2/be_samv2/vmp | Finding VMPs by label with pagination.
*Besamv2Api* | [**findPaginatedVmpsByLabel1**](docs/Besamv2Api.md#findpaginatedvmpsbylabel1) | **GET** /rest/v1/be_samv2/vmp | Finding VMPs by label with pagination.
*Besamv2Api* | [**findPaginatedVmpsByVmpCode**](docs/Besamv2Api.md#findpaginatedvmpsbyvmpcode) | **GET** /rest/v2/be_samv2/vmp/byVmpCode/{vmpCode} | Finding VMPs by group with pagination.
*Besamv2Api* | [**findPaginatedVmpsByVmpCode1**](docs/Besamv2Api.md#findpaginatedvmpsbyvmpcode1) | **GET** /rest/v1/be_samv2/vmp/byVmpCode/{vmpCode} | Finding VMPs by group with pagination.
*Besamv2Api* | [**getSamVersion**](docs/Besamv2Api.md#getsamversion) | **GET** /rest/v2/be_samv2/v | Get Samv2 version.
*Besamv2Api* | [**getSamVersion1**](docs/Besamv2Api.md#getsamversion1) | **GET** /rest/v1/be_samv2/v | Get Samv2 version.
*Besamv2Api* | [**listAmpsByDmppCodes**](docs/Besamv2Api.md#listampsbydmppcodes) | **POST** /rest/v2/be_samv2/amp/byDmppCodes | Finding AMPs by dmpp code
*Besamv2Api* | [**listAmpsByDmppCodes1**](docs/Besamv2Api.md#listampsbydmppcodes1) | **POST** /rest/v1/be_samv2/amp/byDmppCodes | Finding AMPs by dmpp code
*Besamv2Api* | [**listAmpsByGroupCodes**](docs/Besamv2Api.md#listampsbygroupcodes) | **POST** /rest/v2/be_samv2/amp/byGroupCodes | Finding AMPs by group.
*Besamv2Api* | [**listAmpsByGroupCodes1**](docs/Besamv2Api.md#listampsbygroupcodes1) | **POST** /rest/v1/be_samv2/amp/byGroupCodes | Finding AMPs by group.
*Besamv2Api* | [**listAmpsByGroupIds**](docs/Besamv2Api.md#listampsbygroupids) | **POST** /rest/v2/be_samv2/amp/byGroupIds | Finding AMPs by group.
*Besamv2Api* | [**listAmpsByGroupIds1**](docs/Besamv2Api.md#listampsbygroupids1) | **POST** /rest/v1/be_samv2/amp/byGroupIds | Finding AMPs by group.
*Besamv2Api* | [**listAmpsByVmpCodes**](docs/Besamv2Api.md#listampsbyvmpcodes) | **POST** /rest/v2/be_samv2/amp/byVmpCodes | Finding AMPs by vmp code.
*Besamv2Api* | [**listAmpsByVmpCodes1**](docs/Besamv2Api.md#listampsbyvmpcodes1) | **POST** /rest/v1/be_samv2/amp/byVmpCodes | Finding AMPs by vmp code.
*Besamv2Api* | [**listAmpsByVmpIds**](docs/Besamv2Api.md#listampsbyvmpids) | **POST** /rest/v2/be_samv2/amp/byVmpIds | Finding AMPs by vmp id.
*Besamv2Api* | [**listAmpsByVmpIds1**](docs/Besamv2Api.md#listampsbyvmpids1) | **POST** /rest/v1/be_samv2/amp/byVmpIds | Finding AMPs by vmp id.
*Besamv2Api* | [**listNmpsByCnks**](docs/Besamv2Api.md#listnmpsbycnks) | **POST** /rest/v2/be_samv2/nmp/byCnks | Finding NMPs by cnk id.
*Besamv2Api* | [**listNmpsByCnks1**](docs/Besamv2Api.md#listnmpsbycnks1) | **POST** /rest/v1/be_samv2/nmp/byCnks | Finding NMPs by cnk id.
*Besamv2Api* | [**listPharmaceuticalForms**](docs/Besamv2Api.md#listpharmaceuticalforms) | **GET** /rest/v2/be_samv2/pharmaform | List all pharmaceutical forms.
*Besamv2Api* | [**listPharmaceuticalForms1**](docs/Besamv2Api.md#listpharmaceuticalforms1) | **GET** /rest/v1/be_samv2/pharmaform | List all pharmaceutical forms.
*Besamv2Api* | [**listSubstances**](docs/Besamv2Api.md#listsubstances) | **GET** /rest/v2/be_samv2/substance | List all substances.
*Besamv2Api* | [**listSubstances1**](docs/Besamv2Api.md#listsubstances1) | **GET** /rest/v1/be_samv2/substance | List all substances.
*Besamv2Api* | [**listVmpGroupsByVmpGroupCodes**](docs/Besamv2Api.md#listvmpgroupsbyvmpgroupcodes) | **POST** /rest/v2/be_samv2/vmpgroup/byGroupCodes | Finding AMPs by group.
*Besamv2Api* | [**listVmpGroupsByVmpGroupCodes1**](docs/Besamv2Api.md#listvmpgroupsbyvmpgroupcodes1) | **POST** /rest/v1/be_samv2/vmpgroup/byGroupCodes | Finding AMPs by group.
*Besamv2Api* | [**listVmpsByGroupIds**](docs/Besamv2Api.md#listvmpsbygroupids) | **POST** /rest/v2/be_samv2/vmp/byGroupIds | Finding VMPs by group.
*Besamv2Api* | [**listVmpsByGroupIds1**](docs/Besamv2Api.md#listvmpsbygroupids1) | **POST** /rest/v1/be_samv2/vmp/byGroupIds | Finding VMPs by group.
*Besamv2Api* | [**listVmpsByVmpCodes**](docs/Besamv2Api.md#listvmpsbyvmpcodes) | **POST** /rest/v2/be_samv2/vmp/byVmpCodes | Finding VMPs by group.
*Besamv2Api* | [**listVmpsByVmpCodes1**](docs/Besamv2Api.md#listvmpsbyvmpcodes1) | **POST** /rest/v1/be_samv2/vmp/byVmpCodes | Finding VMPs by group.
*CalendarItemApi* | [**createCalendarItem**](docs/CalendarItemApi.md#createcalendaritem) | **POST** /rest/v2/calendarItem | Creates a calendarItem
*CalendarItemApi* | [**createCalendarItem1**](docs/CalendarItemApi.md#createcalendaritem1) | **POST** /rest/v1/calendarItem | Creates a calendarItem
*CalendarItemApi* | [**deleteCalendarItem**](docs/CalendarItemApi.md#deletecalendaritem) | **DELETE** /rest/v1/calendarItem/{calendarItemIds} | Deletes an calendarItem
*CalendarItemApi* | [**deleteCalendarItems**](docs/CalendarItemApi.md#deletecalendaritems) | **DELETE** /rest/v2/calendarItem/delete/batch | Deletes an calendarItem
*CalendarItemApi* | [**findCalendarItemsByHCPartyPatientForeignKeys**](docs/CalendarItemApi.md#findcalendaritemsbyhcpartypatientforeignkeys) | **GET** /rest/v2/calendarItem/byHcPartySecretForeignKeys | Find CalendarItems by hcparty and patient
*CalendarItemApi* | [**findCalendarItemsByHCPartyPatientForeignKeys1**](docs/CalendarItemApi.md#findcalendaritemsbyhcpartypatientforeignkeys1) | **GET** /rest/v1/calendarItem/byHcPartySecretForeignKeys | Find CalendarItems by hcparty and patient
*CalendarItemApi* | [**getCalendarItem**](docs/CalendarItemApi.md#getcalendaritem) | **GET** /rest/v2/calendarItem/{calendarItemId} | Gets an calendarItem
*CalendarItemApi* | [**getCalendarItem1**](docs/CalendarItemApi.md#getcalendaritem1) | **GET** /rest/v1/calendarItem/{calendarItemId} | Gets an calendarItem
*CalendarItemApi* | [**getCalendarItems**](docs/CalendarItemApi.md#getcalendaritems) | **GET** /rest/v2/calendarItem | Gets all calendarItems
*CalendarItemApi* | [**getCalendarItems1**](docs/CalendarItemApi.md#getcalendaritems1) | **GET** /rest/v1/calendarItem | Gets all calendarItems
*CalendarItemApi* | [**getCalendarItemsByPeriodAndHcPartyId**](docs/CalendarItemApi.md#getcalendaritemsbyperiodandhcpartyid) | **POST** /rest/v2/calendarItem/byPeriodAndHcPartyId | Get CalendarItems by Period and HcPartyId
*CalendarItemApi* | [**getCalendarItemsByPeriodAndHcPartyId1**](docs/CalendarItemApi.md#getcalendaritemsbyperiodandhcpartyid1) | **POST** /rest/v1/calendarItem/byPeriodAndHcPartyId | Get CalendarItems by Period and HcPartyId
*CalendarItemApi* | [**getCalendarItemsWithIds**](docs/CalendarItemApi.md#getcalendaritemswithids) | **POST** /rest/v2/calendarItem/byIds | Get calendarItems by ids
*CalendarItemApi* | [**getCalendarItemsWithIds1**](docs/CalendarItemApi.md#getcalendaritemswithids1) | **POST** /rest/v1/calendarItem/byIds | Get calendarItems by id
*CalendarItemApi* | [**getCalendarsByPeriodAndAgendaId**](docs/CalendarItemApi.md#getcalendarsbyperiodandagendaid) | **POST** /rest/v2/calendarItem/byPeriodAndAgendaId | Get CalendarItems by Period and AgendaId
*CalendarItemApi* | [**getCalendarsByPeriodAndAgendaId1**](docs/CalendarItemApi.md#getcalendarsbyperiodandagendaid1) | **POST** /rest/v1/calendarItem/byPeriodAndAgendaId | Get CalendarItems by Period and AgendaId
*CalendarItemApi* | [**modifyCalendarItem**](docs/CalendarItemApi.md#modifycalendaritem) | **PUT** /rest/v2/calendarItem | Modifies an calendarItem
*CalendarItemApi* | [**modifyCalendarItem1**](docs/CalendarItemApi.md#modifycalendaritem1) | **PUT** /rest/v1/calendarItem | Modifies an calendarItem
*CalendarItemApi* | [**setCalendarItemsDelegations**](docs/CalendarItemApi.md#setcalendaritemsdelegations) | **POST** /rest/v2/calendarItem/delegations | Update delegations in calendarItems
*CalendarItemApi* | [**setCalendarItemsDelegations1**](docs/CalendarItemApi.md#setcalendaritemsdelegations1) | **POST** /rest/v1/calendarItem/delegations | Update delegations in calendarItems
*CalendarItemTypeApi* | [**createCalendarItemType**](docs/CalendarItemTypeApi.md#createcalendaritemtype) | **POST** /rest/v2/calendarItemType | Creates a calendarItemType
*CalendarItemTypeApi* | [**createCalendarItemType1**](docs/CalendarItemTypeApi.md#createcalendaritemtype1) | **POST** /rest/v1/calendarItemType | Creates a calendarItemType
*CalendarItemTypeApi* | [**deleteCalendarItemType**](docs/CalendarItemTypeApi.md#deletecalendaritemtype) | **DELETE** /rest/v1/calendarItemType/{calendarItemTypeIds} | Deletes an calendarItemType
*CalendarItemTypeApi* | [**deleteCalendarItemTypes**](docs/CalendarItemTypeApi.md#deletecalendaritemtypes) | **POST** /rest/v2/calendarItemType/delete/batch | Deletes calendarItemTypes
*CalendarItemTypeApi* | [**getCalendarItemType**](docs/CalendarItemTypeApi.md#getcalendaritemtype) | **GET** /rest/v2/calendarItemType/{calendarItemTypeId} | Gets a calendarItemType
*CalendarItemTypeApi* | [**getCalendarItemType1**](docs/CalendarItemTypeApi.md#getcalendaritemtype1) | **GET** /rest/v1/calendarItemType/{calendarItemTypeId} | Gets an calendarItemType
*CalendarItemTypeApi* | [**getCalendarItemTypes**](docs/CalendarItemTypeApi.md#getcalendaritemtypes) | **GET** /rest/v2/calendarItemType | Gets all calendarItemTypes
*CalendarItemTypeApi* | [**getCalendarItemTypes1**](docs/CalendarItemTypeApi.md#getcalendaritemtypes1) | **GET** /rest/v1/calendarItemType | Gets all calendarItemTypes
*CalendarItemTypeApi* | [**getCalendarItemTypesIncludeDeleted**](docs/CalendarItemTypeApi.md#getcalendaritemtypesincludedeleted) | **GET** /rest/v2/calendarItemType/includeDeleted | Gets all calendarItemTypes include deleted
*CalendarItemTypeApi* | [**getCalendarItemTypesIncludeDeleted1**](docs/CalendarItemTypeApi.md#getcalendaritemtypesincludedeleted1) | **GET** /rest/v1/calendarItemType/includeDeleted | Gets all calendarItemTypes include deleted
*CalendarItemTypeApi* | [**modifyCalendarItemType**](docs/CalendarItemTypeApi.md#modifycalendaritemtype) | **PUT** /rest/v2/calendarItemType | Modifies an calendarItemType
*CalendarItemTypeApi* | [**modifyCalendarItemType1**](docs/CalendarItemTypeApi.md#modifycalendaritemtype1) | **PUT** /rest/v1/calendarItemType | Modifies an calendarItemType
*ClassificationApi* | [**createClassification**](docs/ClassificationApi.md#createclassification) | **POST** /rest/v2/classification | Create a classification with the current user
*ClassificationApi* | [**createClassification1**](docs/ClassificationApi.md#createclassification1) | **POST** /rest/v1/classification | Create a classification with the current user
*ClassificationApi* | [**deleteClassifications**](docs/ClassificationApi.md#deleteclassifications) | **POST** /rest/v2/classification/delete/batch | Delete classification Templates.
*ClassificationApi* | [**deleteClassifications1**](docs/ClassificationApi.md#deleteclassifications1) | **DELETE** /rest/v1/classification/{classificationIds} | Delete classification Templates.
*ClassificationApi* | [**findClassificationsByHCPartyPatientForeignKeys**](docs/ClassificationApi.md#findclassificationsbyhcpartypatientforeignkeys) | **GET** /rest/v2/classification/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
*ClassificationApi* | [**findClassificationsByHCPartyPatientForeignKeys1**](docs/ClassificationApi.md#findclassificationsbyhcpartypatientforeignkeys1) | **GET** /rest/v1/classification/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
*ClassificationApi* | [**getClassification**](docs/ClassificationApi.md#getclassification) | **GET** /rest/v2/classification/{classificationId} | Get a classification Template
*ClassificationApi* | [**getClassification1**](docs/ClassificationApi.md#getclassification1) | **GET** /rest/v1/classification/{classificationId} | Get a classification Template
*ClassificationApi* | [**getClassificationByHcPartyId**](docs/ClassificationApi.md#getclassificationbyhcpartyid) | **GET** /rest/v2/classification/byIds/{ids} | Get a list of classifications
*ClassificationApi* | [**getClassificationByHcPartyId1**](docs/ClassificationApi.md#getclassificationbyhcpartyid1) | **GET** /rest/v1/classification/byIds/{ids} | Get a list of classifications
*ClassificationApi* | [**modifyClassification**](docs/ClassificationApi.md#modifyclassification) | **PUT** /rest/v2/classification | Modify a classification Template
*ClassificationApi* | [**modifyClassification1**](docs/ClassificationApi.md#modifyclassification1) | **PUT** /rest/v1/classification | Modify a classification Template
*ClassificationApi* | [**newClassificationDelegations**](docs/ClassificationApi.md#newclassificationdelegations) | **POST** /rest/v2/classification/{classificationId}/delegate | Delegates a classification to a healthcare party
*ClassificationApi* | [**newClassificationDelegations1**](docs/ClassificationApi.md#newclassificationdelegations1) | **POST** /rest/v1/classification/{classificationId}/delegate | Delegates a classification to a healthcare party
*ClassificationApi* | [**setClassificationsDelegations**](docs/ClassificationApi.md#setclassificationsdelegations) | **POST** /rest/v2/classification/delegations | Update delegations in classification
*ClassificationApi* | [**setClassificationsDelegations1**](docs/ClassificationApi.md#setclassificationsdelegations1) | **POST** /rest/v1/classification/delegations | Update delegations in classification
*ClassificationTemplateApi* | [**createClassificationTemplate**](docs/ClassificationTemplateApi.md#createclassificationtemplate) | **POST** /rest/v2/classificationTemplate | Create a classification Template with the current user
*ClassificationTemplateApi* | [**createClassificationTemplate1**](docs/ClassificationTemplateApi.md#createclassificationtemplate1) | **POST** /rest/v1/classificationTemplate | Create a classification Template with the current user
*ClassificationTemplateApi* | [**deleteClassificationTemplates**](docs/ClassificationTemplateApi.md#deleteclassificationtemplates) | **POST** /rest/v2/classificationTemplate/delete/batch | Delete classification Templates.
*ClassificationTemplateApi* | [**deleteClassificationTemplates1**](docs/ClassificationTemplateApi.md#deleteclassificationtemplates1) | **DELETE** /rest/v1/classificationTemplate/{classificationTemplateIds} | Delete classification Templates.
*ClassificationTemplateApi* | [**findClassificationTemplatesBy**](docs/ClassificationTemplateApi.md#findclassificationtemplatesby) | **GET** /rest/v2/classificationTemplate | List all classification templates with pagination
*ClassificationTemplateApi* | [**findClassificationTemplatesByHCPartyPatientForeignKeys**](docs/ClassificationTemplateApi.md#findclassificationtemplatesbyhcpartypatientforeignkeys) | **GET** /rest/v1/classificationTemplate/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
*ClassificationTemplateApi* | [**getClassificationTemplate**](docs/ClassificationTemplateApi.md#getclassificationtemplate) | **GET** /rest/v2/classificationTemplate/{classificationTemplateId} | Get a classification Template
*ClassificationTemplateApi* | [**getClassificationTemplate1**](docs/ClassificationTemplateApi.md#getclassificationtemplate1) | **GET** /rest/v1/classificationTemplate/{classificationTemplateId} | Get a classification Template
*ClassificationTemplateApi* | [**getClassificationTemplateByIds**](docs/ClassificationTemplateApi.md#getclassificationtemplatebyids) | **GET** /rest/v2/classificationTemplate/byIds/{ids} | Get a list of classifications Templates
*ClassificationTemplateApi* | [**getClassificationTemplateByIds1**](docs/ClassificationTemplateApi.md#getclassificationtemplatebyids1) | **GET** /rest/v1/classificationTemplate/byIds/{ids} | Get a list of classifications Templates
*ClassificationTemplateApi* | [**listClassificationTemplates**](docs/ClassificationTemplateApi.md#listclassificationtemplates) | **GET** /rest/v1/classificationTemplate | List all classification templates with pagination
*ClassificationTemplateApi* | [**listClassificationTemplatesByHCPartyPatientForeignKeys**](docs/ClassificationTemplateApi.md#listclassificationtemplatesbyhcpartypatientforeignkeys) | **GET** /rest/v2/classificationTemplate/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
*ClassificationTemplateApi* | [**modifyClassificationTemplate**](docs/ClassificationTemplateApi.md#modifyclassificationtemplate) | **PUT** /rest/v2/classificationTemplate | Modify a classification Template
*ClassificationTemplateApi* | [**modifyClassificationTemplate1**](docs/ClassificationTemplateApi.md#modifyclassificationtemplate1) | **PUT** /rest/v1/classificationTemplate | Modify a classification Template
*ClassificationTemplateApi* | [**newClassificationTemplateDelegations**](docs/ClassificationTemplateApi.md#newclassificationtemplatedelegations) | **POST** /rest/v2/classificationTemplate/{classificationTemplateId}/delegate | Delegates a classification Template to a healthcare party
*ClassificationTemplateApi* | [**newClassificationTemplateDelegations1**](docs/ClassificationTemplateApi.md#newclassificationtemplatedelegations1) | **POST** /rest/v1/classificationTemplate/{classificationTemplateId}/delegate | Delegates a classification Template to a healthcare party
*CodeApi* | [**createCode**](docs/CodeApi.md#createcode) | **POST** /rest/v2/code | Create a Code
*CodeApi* | [**createCode1**](docs/CodeApi.md#createcode1) | **POST** /rest/v1/code | Create a code
*CodeApi* | [**filterCodesBy**](docs/CodeApi.md#filtercodesby) | **POST** /rest/v2/code/filter | Filter codes 
*CodeApi* | [**filterCodesBy1**](docs/CodeApi.md#filtercodesby1) | **POST** /rest/v1/code/filter | Filter codes
*CodeApi* | [**findCodeTypes**](docs/CodeApi.md#findcodetypes) | **GET** /rest/v1/code/codetype/byRegionType | Get list of code types by region and type.
*CodeApi* | [**findCodes**](docs/CodeApi.md#findcodes) | **GET** /rest/v1/code/byRegionTypeCode | Gets list of codes by code, type and version
*CodeApi* | [**findCodesByLabel**](docs/CodeApi.md#findcodesbylabel) | **GET** /rest/v2/code/byLabel | Finding codes by code, type and version with pagination.
*CodeApi* | [**findCodesByLink**](docs/CodeApi.md#findcodesbylink) | **GET** /rest/v2/code/byLink/{linkType} | Finding codes by code, type and version with pagination.
*CodeApi* | [**findCodesByType**](docs/CodeApi.md#findcodesbytype) | **GET** /rest/v2/code | Finding codes by code, type and version with pagination.
*CodeApi* | [**findPaginatedCodes**](docs/CodeApi.md#findpaginatedcodes) | **GET** /rest/v1/code | Gets paginated list of codes by code, type and version.
*CodeApi* | [**findPaginatedCodesByLabel**](docs/CodeApi.md#findpaginatedcodesbylabel) | **GET** /rest/v1/code/byLabel | Get paginated list of codes by code, type and version.
*CodeApi* | [**findPaginatedCodesWithLink**](docs/CodeApi.md#findpaginatedcodeswithlink) | **GET** /rest/v1/code/link/{linkType} | Gets paginated list of codes by link and link type.
*CodeApi* | [**findTagTypes**](docs/CodeApi.md#findtagtypes) | **GET** /rest/v1/code/tagtype/byRegionType | Gets list of tag types by region and type.
*CodeApi* | [**getCode**](docs/CodeApi.md#getcode) | **GET** /rest/v2/code/{codeId} | Get a code
*CodeApi* | [**getCode1**](docs/CodeApi.md#getcode1) | **GET** /rest/v1/code/{codeId} | Get a code by id
*CodeApi* | [**getCodeWithParts**](docs/CodeApi.md#getcodewithparts) | **GET** /rest/v2/code/{type}/{code}/{version} | Get a code
*CodeApi* | [**getCodeWithParts1**](docs/CodeApi.md#getcodewithparts1) | **GET** /rest/v1/code/{type}/{code}/{version} | Get a code
*CodeApi* | [**getCodes**](docs/CodeApi.md#getcodes) | **POST** /rest/v2/code/byIds | Get a list of codes by ids
*CodeApi* | [**getCodes1**](docs/CodeApi.md#getcodes1) | **GET** /rest/v1/code/byIds/{codeIds} | Gets a list of codes by ids
*CodeApi* | [**listCodeTypesBy**](docs/CodeApi.md#listcodetypesby) | **GET** /rest/v2/code/codetype/byRegionType | Finding code types.
*CodeApi* | [**listCodesByRegionTypeCodeVersion**](docs/CodeApi.md#listcodesbyregiontypecodeversion) | **GET** /rest/v2/code/byRegionTypeCode | Finding codes by code, type and version
*CodeApi* | [**listTagTypesBy**](docs/CodeApi.md#listtagtypesby) | **GET** /rest/v2/code/tagtype/byRegionType | Finding tag types.
*CodeApi* | [**modifyCode**](docs/CodeApi.md#modifycode) | **PUT** /rest/v2/code | Modify a code
*CodeApi* | [**modifyCode1**](docs/CodeApi.md#modifycode1) | **PUT** /rest/v1/code | Modify a code
*ContactApi* | [**closeForHCPartyPatientForeignKeys**](docs/ContactApi.md#closeforhcpartypatientforeignkeys) | **PUT** /rest/v2/contact/byHcPartySecretForeignKeys/close | Close contacts for Healthcare Party and secret foreign keys.
*ContactApi* | [**closeForHCPartyPatientForeignKeys1**](docs/ContactApi.md#closeforhcpartypatientforeignkeys1) | **PUT** /rest/v1/contact/byHcPartySecretForeignKeys/close | Close contacts for Healthcare Party and secret foreign keys.
*ContactApi* | [**createContact**](docs/ContactApi.md#createcontact) | **POST** /rest/v2/contact | Create a contact with the current user
*ContactApi* | [**createContact1**](docs/ContactApi.md#createcontact1) | **POST** /rest/v1/contact | Create a contact with the current user
*ContactApi* | [**createContacts**](docs/ContactApi.md#createcontacts) | **POST** /rest/v2/contact/batch | Create a batch of contacts
*ContactApi* | [**createContacts1**](docs/ContactApi.md#createcontacts1) | **POST** /rest/v1/contact/batch | Create a batch of contacts
*ContactApi* | [**deleteContacts**](docs/ContactApi.md#deletecontacts) | **POST** /rest/v2/contact/delete/batch | Delete contacts.
*ContactApi* | [**deleteContacts1**](docs/ContactApi.md#deletecontacts1) | **DELETE** /rest/v1/contact/{contactIds} | Delete contacts.
*ContactApi* | [**filterContactsBy**](docs/ContactApi.md#filtercontactsby) | **POST** /rest/v2/contact/filter | List contacts for the current user (HcParty) or the given hcparty in the filter 
*ContactApi* | [**filterContactsBy1**](docs/ContactApi.md#filtercontactsby1) | **POST** /rest/v1/contact/filter | List contacts for the current user (HcParty) or the given hcparty in the filter 
*ContactApi* | [**filterServicesBy**](docs/ContactApi.md#filterservicesby) | **POST** /rest/v2/contact/service/filter | List services for the current user (HcParty) or the given hcparty in the filter 
*ContactApi* | [**filterServicesBy1**](docs/ContactApi.md#filterservicesby1) | **POST** /rest/v1/contact/service/filter | List services for the current user (HcParty) or the given hcparty in the filter 
*ContactApi* | [**findByHCPartyFormId**](docs/ContactApi.md#findbyhcpartyformid) | **GET** /rest/v1/contact/byHcPartyFormId | Get a list of contacts found by Healthcare Party and form's id.
*ContactApi* | [**findByHCPartyFormIds**](docs/ContactApi.md#findbyhcpartyformids) | **POST** /rest/v1/contact/byHcPartyFormIds | Get a list of contacts found by Healthcare Party and form's ids.
*ContactApi* | [**findByHCPartyPatientSecretFKeys**](docs/ContactApi.md#findbyhcpartypatientsecretfkeys) | **GET** /rest/v1/contact/byHcPartySecretForeignKeys | Get a list of contacts found by Healthcare Party and secret foreign keys.
*ContactApi* | [**findByHCPartyServiceId**](docs/ContactApi.md#findbyhcpartyserviceid) | **GET** /rest/v1/contact/byHcPartyServiceId | List contacts found By Healthcare Party and service Id.
*ContactApi* | [**findContactsByExternalId**](docs/ContactApi.md#findcontactsbyexternalid) | **POST** /rest/v1/contact/byExternalId | List contacts found By externalId.
*ContactApi* | [**findContactsByHCPartyPatientForeignKeys**](docs/ContactApi.md#findcontactsbyhcpartypatientforeignkeys) | **POST** /rest/v1/contact/byHcPartyPatientForeignKeys | Get a list of contacts found by Healthcare Party and Patient foreign keys.
*ContactApi* | [**findContactsByOpeningDate**](docs/ContactApi.md#findcontactsbyopeningdate) | **GET** /rest/v2/contact/byOpeningDate | List contacts by opening date parties with(out) pagination
*ContactApi* | [**findContactsDelegationsStubsByHCPartyPatientForeignKeys**](docs/ContactApi.md#findcontactsdelegationsstubsbyhcpartypatientforeignkeys) | **GET** /rest/v1/contact/byHcPartySecretForeignKeys/delegations | List contacts found By Healthcare Party and secret foreign keys.
*ContactApi* | [**getContact**](docs/ContactApi.md#getcontact) | **GET** /rest/v2/contact/{contactId} | Get a contact
*ContactApi* | [**getContact1**](docs/ContactApi.md#getcontact1) | **GET** /rest/v1/contact/{contactId} | Get a contact
*ContactApi* | [**getContacts**](docs/ContactApi.md#getcontacts) | **POST** /rest/v2/contact/byIds | Get contacts
*ContactApi* | [**getContacts1**](docs/ContactApi.md#getcontacts1) | **POST** /rest/v1/contact/byIds | Get contacts by batch
*ContactApi* | [**getEmptyContent**](docs/ContactApi.md#getemptycontent) | **GET** /rest/v2/contact/service/content/empty | Get an empty content
*ContactApi* | [**getEmptyContent1**](docs/ContactApi.md#getemptycontent1) | **GET** /rest/v1/contact/service/content/empty | Get an empty content
*ContactApi* | [**getServiceCodesOccurences**](docs/ContactApi.md#getservicecodesoccurences) | **GET** /rest/v2/contact/service/codes/{codeType}/{minOccurences} | Get the list of all used codes frequencies in services
*ContactApi* | [**getServiceCodesOccurences1**](docs/ContactApi.md#getservicecodesoccurences1) | **GET** /rest/v1/contact/service/codes/{codeType}/{minOccurences} | Get the list of all used codes frequencies in services
*ContactApi* | [**getServices**](docs/ContactApi.md#getservices) | **POST** /rest/v2/contact/service | List services with provided ids 
*ContactApi* | [**getServicesLinkedTo**](docs/ContactApi.md#getserviceslinkedto) | **POST** /rest/v2/contact/service/linkedTo | List services linked to provided ids 
*ContactApi* | [**listContactsByHCPartyAndFormId**](docs/ContactApi.md#listcontactsbyhcpartyandformid) | **GET** /rest/v2/contact/byHcPartyFormId | List contacts found By Healthcare Party and form Id.
*ContactApi* | [**listContactsByHCPartyAndFormIds**](docs/ContactApi.md#listcontactsbyhcpartyandformids) | **POST** /rest/v2/contact/byHcPartyFormIds | List contacts found By Healthcare Party and form Id.
*ContactApi* | [**listContactsByHCPartyAndPatientForeignKeys**](docs/ContactApi.md#listcontactsbyhcpartyandpatientforeignkeys) | **POST** /rest/v2/contact/byHcPartyPatientForeignKeys | List contacts found By Healthcare Party and Patient foreign keys.
*ContactApi* | [**listContactsByHCPartyAndPatientSecretFKeys**](docs/ContactApi.md#listcontactsbyhcpartyandpatientsecretfkeys) | **GET** /rest/v2/contact/byHcPartySecretForeignKeys | List contacts found By Healthcare Party and secret foreign keys.
*ContactApi* | [**listContactsByOpeningDate**](docs/ContactApi.md#listcontactsbyopeningdate) | **GET** /rest/v1/contact/byOpeningDate | List contacts bu opening date parties with(out) pagination
*ContactApi* | [**listContactsDelegationsStubsByHCPartyAndPatientForeignKeys**](docs/ContactApi.md#listcontactsdelegationsstubsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/contact/byHcPartySecretForeignKeys/delegations | List contacts found By Healthcare Party and secret foreign keys.
*ContactApi* | [**listServices**](docs/ContactApi.md#listservices) | **POST** /rest/v1/contact/service/byIds | List services with provided ids 
*ContactApi* | [**listServicesByAssociationId**](docs/ContactApi.md#listservicesbyassociationid) | **GET** /rest/v1/contact/service/associationId | List services by related association id
*ContactApi* | [**listServicesLinkedTo**](docs/ContactApi.md#listserviceslinkedto) | **POST** /rest/v1/contact/service/linkedTo | List services linked to provided ids 
*ContactApi* | [**matchContactsBy**](docs/ContactApi.md#matchcontactsby) | **POST** /rest/v2/contact/match | Get ids of contacts matching the provided filter for the current user (HcParty) 
*ContactApi* | [**matchContactsBy1**](docs/ContactApi.md#matchcontactsby1) | **POST** /rest/v1/contact/match | Get ids of contacts matching the provided filter for the current user (HcParty) 
*ContactApi* | [**modifyContact**](docs/ContactApi.md#modifycontact) | **PUT** /rest/v2/contact | Modify a contact
*ContactApi* | [**modifyContact1**](docs/ContactApi.md#modifycontact1) | **PUT** /rest/v1/contact | Modify a contact
*ContactApi* | [**modifyContacts**](docs/ContactApi.md#modifycontacts) | **PUT** /rest/v2/contact/batch | Modify a batch of contacts
*ContactApi* | [**modifyContacts1**](docs/ContactApi.md#modifycontacts1) | **PUT** /rest/v1/contact/batch | Modify a batch of contacts
*ContactApi* | [**modifyContactsDelegations**](docs/ContactApi.md#modifycontactsdelegations) | **PUT** /rest/v2/contact/delegations | Update delegations in healthElements.
*ContactApi* | [**newContactDelegations**](docs/ContactApi.md#newcontactdelegations) | **POST** /rest/v2/contact/{contactId}/delegate | Delegates a contact to a healthcare party
*ContactApi* | [**newContactDelegations1**](docs/ContactApi.md#newcontactdelegations1) | **POST** /rest/v1/contact/{contactId}/delegate | Delegates a contact to a healthcare party
*ContactApi* | [**setContactsDelegations**](docs/ContactApi.md#setcontactsdelegations) | **POST** /rest/v1/contact/delegations | Update delegations in healthElements.
*DoctemplateApi* | [**createDocumentTemplate**](docs/DoctemplateApi.md#createdocumenttemplate) | **POST** /rest/v2/doctemplate | Create a document template with the current user
*DoctemplateApi* | [**createDocumentTemplate1**](docs/DoctemplateApi.md#createdocumenttemplate1) | **POST** /rest/v1/doctemplate | Create a document template with the current user
*DoctemplateApi* | [**deleteDocumentTemplate**](docs/DoctemplateApi.md#deletedocumenttemplate) | **DELETE** /rest/v1/doctemplate/{documentTemplateIds} | Deletes a document template
*DoctemplateApi* | [**deleteDocumentTemplates**](docs/DoctemplateApi.md#deletedocumenttemplates) | **POST** /rest/v2/doctemplate/delete/batch | Deletes document templates
*DoctemplateApi* | [**findAllDocumentTemplates**](docs/DoctemplateApi.md#findalldocumenttemplates) | **GET** /rest/v1/doctemplate/find/all | Gets all document templates for all users
*DoctemplateApi* | [**findDocumentTemplates**](docs/DoctemplateApi.md#finddocumenttemplates) | **GET** /rest/v1/doctemplate | Gets all document templates for current user
*DoctemplateApi* | [**findDocumentTemplatesByDocumentType**](docs/DoctemplateApi.md#finddocumenttemplatesbydocumenttype) | **GET** /rest/v1/doctemplate/byDocumentType/{documentTypeCode} | Gets all document templates by Type
*DoctemplateApi* | [**findDocumentTemplatesByDocumentTypeForCurrentUser**](docs/DoctemplateApi.md#finddocumenttemplatesbydocumenttypeforcurrentuser) | **GET** /rest/v1/doctemplate/byDocumentTypeForCurrentUser/{documentTypeCode} | Gets all document templates by Type For currentUser
*DoctemplateApi* | [**findDocumentTemplatesBySpeciality**](docs/DoctemplateApi.md#finddocumenttemplatesbyspeciality) | **GET** /rest/v1/doctemplate/bySpecialty/{specialityCode} | Gets all document templates
*DoctemplateApi* | [**getAttachmentText**](docs/DoctemplateApi.md#getattachmenttext) | **GET** /rest/v2/doctemplate/{documentTemplateId}/attachmentText/{attachmentId} | Download a the document template attachment
*DoctemplateApi* | [**getAttachmentText1**](docs/DoctemplateApi.md#getattachmenttext1) | **GET** /rest/v1/doctemplate/{documentTemplateId}/attachmentText/{attachmentId} | Download a the document template attachment
*DoctemplateApi* | [**getDocumentTemplate**](docs/DoctemplateApi.md#getdocumenttemplate) | **GET** /rest/v2/doctemplate/{documentTemplateId} | Gets a document template
*DoctemplateApi* | [**getDocumentTemplate1**](docs/DoctemplateApi.md#getdocumenttemplate1) | **GET** /rest/v1/doctemplate/{documentTemplateId} | Gets a document template
*DoctemplateApi* | [**getDocumentTemplateAttachment**](docs/DoctemplateApi.md#getdocumenttemplateattachment) | **GET** /rest/v2/doctemplate/{documentTemplateId}/attachment/{attachmentId} | Download a the document template attachment
*DoctemplateApi* | [**getDocumentTemplateAttachment1**](docs/DoctemplateApi.md#getdocumenttemplateattachment1) | **GET** /rest/v1/doctemplate/{documentTemplateId}/attachment/{attachmentId} | Download a the document template attachment
*DoctemplateApi* | [**listAllDocumentTemplates**](docs/DoctemplateApi.md#listalldocumenttemplates) | **GET** /rest/v2/doctemplate/find/all | Gets all document templates for all users
*DoctemplateApi* | [**listDocumentTemplates**](docs/DoctemplateApi.md#listdocumenttemplates) | **GET** /rest/v2/doctemplate | Gets all document templates for current user
*DoctemplateApi* | [**listDocumentTemplatesByDocumentType**](docs/DoctemplateApi.md#listdocumenttemplatesbydocumenttype) | **GET** /rest/v2/doctemplate/byDocumentType/{documentTypeCode} | Gets all document templates by Type
*DoctemplateApi* | [**listDocumentTemplatesByDocumentTypeForCurrentUser**](docs/DoctemplateApi.md#listdocumenttemplatesbydocumenttypeforcurrentuser) | **GET** /rest/v2/doctemplate/byDocumentTypeForCurrentUser/{documentTypeCode} | Gets all document templates by Type For currentUser
*DoctemplateApi* | [**listDocumentTemplatesBySpeciality**](docs/DoctemplateApi.md#listdocumenttemplatesbyspeciality) | **GET** /rest/v2/doctemplate/bySpecialty/{specialityCode} | Gets all document templates
*DoctemplateApi* | [**modifyDocumentTemplate**](docs/DoctemplateApi.md#modifydocumenttemplate) | **PUT** /rest/v2/doctemplate/{documentTemplateId} | Modify a document template with the current user
*DoctemplateApi* | [**setDocumentTemplateAttachment**](docs/DoctemplateApi.md#setdocumenttemplateattachment) | **PUT** /rest/v2/doctemplate/{documentTemplateId}/attachment | Creates a document's attachment
*DoctemplateApi* | [**setDocumentTemplateAttachment1**](docs/DoctemplateApi.md#setdocumenttemplateattachment1) | **PUT** /rest/v1/doctemplate/{documentTemplateId}/attachment | Creates a document's attachment
*DoctemplateApi* | [**setDocumentTemplateAttachmentJson**](docs/DoctemplateApi.md#setdocumenttemplateattachmentjson) | **PUT** /rest/v2/doctemplate/{documentTemplateId}/attachmentJson | Creates a document's attachment
*DoctemplateApi* | [**setDocumentTemplateAttachmentJson1**](docs/DoctemplateApi.md#setdocumenttemplateattachmentjson1) | **PUT** /rest/v1/doctemplate/{documentTemplateId}/attachmentJson | Creates a document's attachment
*DoctemplateApi* | [**updateDocumentTemplate**](docs/DoctemplateApi.md#updatedocumenttemplate) | **PUT** /rest/v1/doctemplate/{documentTemplateId} | Modify a document template with the current user
*DocumentApi* | [**createDocument**](docs/DocumentApi.md#createdocument) | **POST** /rest/v2/document | Creates a document
*DocumentApi* | [**createDocument1**](docs/DocumentApi.md#createdocument1) | **POST** /rest/v1/document | Creates a document
*DocumentApi* | [**deleteAttachment**](docs/DocumentApi.md#deleteattachment) | **DELETE** /rest/v2/document/{documentId}/attachment | Deletes a document's attachment
*DocumentApi* | [**deleteAttachment1**](docs/DocumentApi.md#deleteattachment1) | **DELETE** /rest/v1/document/{documentId}/attachment | Deletes a document's attachment
*DocumentApi* | [**deleteDocument**](docs/DocumentApi.md#deletedocument) | **POST** /rest/v2/document/delete/batch | Deletes documents
*DocumentApi* | [**deleteDocument1**](docs/DocumentApi.md#deletedocument1) | **DELETE** /rest/v1/document/{documentIds} | Deletes a document
*DocumentApi* | [**findWithoutDelegation**](docs/DocumentApi.md#findwithoutdelegation) | **GET** /rest/v2/document/woDelegation | List documents with no delegation
*DocumentApi* | [**getDocument**](docs/DocumentApi.md#getdocument) | **GET** /rest/v2/document/{documentId} | Gets a document
*DocumentApi* | [**getDocument1**](docs/DocumentApi.md#getdocument1) | **GET** /rest/v1/document/{documentId} | Gets a document
*DocumentApi* | [**getDocumentAttachment**](docs/DocumentApi.md#getdocumentattachment) | **GET** /rest/v2/document/{documentId}/attachment/{attachmentId} | Load document's attachment
*DocumentApi* | [**getDocumentAttachment1**](docs/DocumentApi.md#getdocumentattachment1) | **GET** /rest/v1/document/{documentId}/attachment/{attachmentId} | Load document's attachment
*DocumentApi* | [**getDocumentByExternalUuid**](docs/DocumentApi.md#getdocumentbyexternaluuid) | **GET** /rest/v2/document/externaluuid/{externalUuid} | Gets a document
*DocumentApi* | [**getDocumentByExternalUuid1**](docs/DocumentApi.md#getdocumentbyexternaluuid1) | **GET** /rest/v1/document/externaluuid/{externalUuid} | Gets a document
*DocumentApi* | [**getDocuments**](docs/DocumentApi.md#getdocuments) | **POST** /rest/v2/document/byIds | Gets a document
*DocumentApi* | [**getDocuments1**](docs/DocumentApi.md#getdocuments1) | **POST** /rest/v1/document/batch | Gets a document
*DocumentApi* | [**getDocumentsByExternalUuid**](docs/DocumentApi.md#getdocumentsbyexternaluuid) | **GET** /rest/v2/document/externaluuid/{externalUuid}/all | Get all documents with externalUuid
*DocumentApi* | [**getDocumentsByExternalUuid1**](docs/DocumentApi.md#getdocumentsbyexternaluuid1) | **GET** /rest/v1/document/externaluuid/{externalUuid}/all | Get all documents with externalUuid
*DocumentApi* | [**listDocumentByTypeHCPartyMessageSecretFKeys**](docs/DocumentApi.md#listdocumentbytypehcpartymessagesecretfkeys) | **GET** /rest/v2/document/byTypeHcPartySecretForeignKeys | List documents found By type, By Healthcare Party and secret foreign keys.
*DocumentApi* | [**listDocumentsByHCPartyAndPatientForeignKeys**](docs/DocumentApi.md#listdocumentsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/document/byHcPartySecretForeignKeys | List documents found By Healthcare Party and secret foreign keys.
*DocumentApi* | [**listDocumentsByHCPartyPatientForeignKeys**](docs/DocumentApi.md#listdocumentsbyhcpartypatientforeignkeys) | **GET** /rest/v1/document/byHcPartySecretForeignKeys | List documents found By Healthcare Party and secret foreign keys.
*DocumentApi* | [**listDocumentsByTypeHCPartyMessageSecretFKeys**](docs/DocumentApi.md#listdocumentsbytypehcpartymessagesecretfkeys) | **GET** /rest/v1/document/byTypeHcPartySecretForeignKeys | List documents found By type, By Healthcare Party and secret foreign keys.
*DocumentApi* | [**listWithoutDelegation**](docs/DocumentApi.md#listwithoutdelegation) | **GET** /rest/v1/document/woDelegation | List documents with no delegation
*DocumentApi* | [**modifyDocument**](docs/DocumentApi.md#modifydocument) | **PUT** /rest/v2/document | Updates a document
*DocumentApi* | [**modifyDocument1**](docs/DocumentApi.md#modifydocument1) | **PUT** /rest/v1/document | Updates a document
*DocumentApi* | [**modifyDocuments**](docs/DocumentApi.md#modifydocuments) | **PUT** /rest/v2/document/batch | Updates a batch of documents
*DocumentApi* | [**modifyDocuments1**](docs/DocumentApi.md#modifydocuments1) | **PUT** /rest/v1/document/batch | Updates a batch of documents
*DocumentApi* | [**setDocumentAttachment**](docs/DocumentApi.md#setdocumentattachment) | **PUT** /rest/v2/document/{documentId}/attachment | Creates a document's attachment
*DocumentApi* | [**setDocumentAttachment1**](docs/DocumentApi.md#setdocumentattachment1) | **PUT** /rest/v1/document/{documentId}/attachment | Creates a document's attachment
*DocumentApi* | [**setDocumentAttachmentMulti**](docs/DocumentApi.md#setdocumentattachmentmulti) | **PUT** /rest/v2/document/{documentId}/attachment/multipart | Creates a document's attachment
*DocumentApi* | [**setDocumentAttachmentMulti1**](docs/DocumentApi.md#setdocumentattachmentmulti1) | **PUT** /rest/v1/document/{documentId}/attachment/multipart | Creates a document's attachment
*DocumentApi* | [**setDocumentsDelegations**](docs/DocumentApi.md#setdocumentsdelegations) | **POST** /rest/v2/document/delegations | Update delegations in healthElements.
*DocumentApi* | [**setDocumentsDelegations1**](docs/DocumentApi.md#setdocumentsdelegations1) | **POST** /rest/v1/document/delegations | Update delegations in healthElements.
*DocumentApi* | [**setSafeDocumentAttachment**](docs/DocumentApi.md#setsafedocumentattachment) | **PUT** /rest/v2/document/attachment | Creates a document's attachment
*DocumentApi* | [**setSafeDocumentAttachment1**](docs/DocumentApi.md#setsafedocumentattachment1) | **PUT** /rest/v1/document/attachment | Creates a document's attachment
*EntityrefApi* | [**createEntityReference**](docs/EntityrefApi.md#createentityreference) | **POST** /rest/v2/entityref | Create an entity reference
*EntityrefApi* | [**createEntityReference1**](docs/EntityrefApi.md#createentityreference1) | **POST** /rest/v1/entityref | Create an entity reference
*EntityrefApi* | [**getLatest**](docs/EntityrefApi.md#getlatest) | **GET** /rest/v2/entityref/latest/{prefix} | Find latest reference for a prefix 
*EntityrefApi* | [**getLatest1**](docs/EntityrefApi.md#getlatest1) | **GET** /rest/v1/entityref/latest/{prefix} | Find latest reference for a prefix 
*EntitytemplateApi* | [**createEntityTemplate**](docs/EntitytemplateApi.md#createentitytemplate) | **POST** /rest/v2/entitytemplate | Create a EntityTemplate
*EntitytemplateApi* | [**createEntityTemplate1**](docs/EntitytemplateApi.md#createentitytemplate1) | **POST** /rest/v1/entitytemplate | Create a EntityTemplate
*EntitytemplateApi* | [**createEntityTemplates**](docs/EntitytemplateApi.md#createentitytemplates) | **POST** /rest/v2/entitytemplate/batch | Create a batch of entityTemplates
*EntitytemplateApi* | [**createEntityTemplates1**](docs/EntitytemplateApi.md#createentitytemplates1) | **POST** /rest/v1/entitytemplate/batch | Create a batch of entityTemplates
*EntitytemplateApi* | [**deleteEntityTemplate**](docs/EntitytemplateApi.md#deleteentitytemplate) | **POST** /rest/v2/entitytemplate/delete/batch | Delete entity templates
*EntitytemplateApi* | [**deleteEntityTemplate1**](docs/EntitytemplateApi.md#deleteentitytemplate1) | **DELETE** /rest/v1/entitytemplate/{entityTemplateIds} | Delete entity templates
*EntitytemplateApi* | [**findAllEntityTemplates**](docs/EntitytemplateApi.md#findallentitytemplates) | **GET** /rest/v1/entitytemplate/findAll/{type} | Finding entityTemplates by entityTemplate, type and version with pagination.
*EntitytemplateApi* | [**findAllEntityTemplatesByKeyword**](docs/EntitytemplateApi.md#findallentitytemplatesbykeyword) | **GET** /rest/v2/entitytemplate/findAll/{type}/keyword/{keyword} | Finding entityTemplates by entityTemplate, type and version with pagination.
*EntitytemplateApi* | [**findAllEntityTemplatesByKeyword1**](docs/EntitytemplateApi.md#findallentitytemplatesbykeyword1) | **GET** /rest/v1/entitytemplate/findAll/{type}/keyword/{keyword} | Finding entityTemplates by entityTemplate, type and version with pagination.
*EntitytemplateApi* | [**findEntityTemplates**](docs/EntitytemplateApi.md#findentitytemplates) | **GET** /rest/v1/entitytemplate/find/{userId}/{type} | Finding entityTemplates by userId, entityTemplate, type and version with pagination.
*EntitytemplateApi* | [**findEntityTemplatesByKeyword**](docs/EntitytemplateApi.md#findentitytemplatesbykeyword) | **GET** /rest/v1/entitytemplate/find/{userId}/{type}/keyword/{keyword} | Finding entityTemplates by userId, type and keyword.
*EntitytemplateApi* | [**getEntityTemplate**](docs/EntitytemplateApi.md#getentitytemplate) | **GET** /rest/v2/entitytemplate/{entityTemplateId} | Get a entityTemplate
*EntitytemplateApi* | [**getEntityTemplate1**](docs/EntitytemplateApi.md#getentitytemplate1) | **GET** /rest/v1/entitytemplate/{entityTemplateId} | Get a entityTemplate
*EntitytemplateApi* | [**getEntityTemplates**](docs/EntitytemplateApi.md#getentitytemplates) | **POST** /rest/v2/entitytemplate/byIds | Get a list of entityTemplates by ids
*EntitytemplateApi* | [**getEntityTemplates1**](docs/EntitytemplateApi.md#getentitytemplates1) | **GET** /rest/v1/entitytemplate/byIds/{entityTemplateIds} | Get a list of entityTemplates by ids
*EntitytemplateApi* | [**listAllEntityTemplatesBy**](docs/EntitytemplateApi.md#listallentitytemplatesby) | **GET** /rest/v2/entitytemplate/findAll/{type} | Finding entityTemplates by entityTemplate, type and version with pagination.
*EntitytemplateApi* | [**listEntityTemplatesBy**](docs/EntitytemplateApi.md#listentitytemplatesby) | **GET** /rest/v2/entitytemplate/find/{userId}/{type} | Finding entityTemplates by userId, entityTemplate, type and version with pagination.
*EntitytemplateApi* | [**listEntityTemplatesByKeyword**](docs/EntitytemplateApi.md#listentitytemplatesbykeyword) | **GET** /rest/v2/entitytemplate/find/{userId}/{type}/keyword/{keyword} | Finding entityTemplates by userId, type and keyword.
*EntitytemplateApi* | [**modifyEntityTemplate**](docs/EntitytemplateApi.md#modifyentitytemplate) | **PUT** /rest/v2/entitytemplate | Modify a entityTemplate
*EntitytemplateApi* | [**modifyEntityTemplate1**](docs/EntitytemplateApi.md#modifyentitytemplate1) | **PUT** /rest/v1/entitytemplate | Modify a entityTemplate
*EntitytemplateApi* | [**modifyEntityTemplates**](docs/EntitytemplateApi.md#modifyentitytemplates) | **PUT** /rest/v2/entitytemplate/batch | Modify a batch of entityTemplates
*EntitytemplateApi* | [**modifyEntityTemplates1**](docs/EntitytemplateApi.md#modifyentitytemplates1) | **PUT** /rest/v1/entitytemplate/batch | Modify a batch of entityTemplates
*FormApi* | [**createForm**](docs/FormApi.md#createform) | **POST** /rest/v2/form | Create a form with the current user
*FormApi* | [**createForm1**](docs/FormApi.md#createform1) | **POST** /rest/v1/form | Create a form with the current user
*FormApi* | [**createFormTemplate**](docs/FormApi.md#createformtemplate) | **POST** /rest/v2/form/template | Create a form template with the current user
*FormApi* | [**createFormTemplate1**](docs/FormApi.md#createformtemplate1) | **POST** /rest/v1/form/template | Create a form template with the current user
*FormApi* | [**createForms**](docs/FormApi.md#createforms) | **POST** /rest/v2/form/batch | Create a batch of forms
*FormApi* | [**createForms1**](docs/FormApi.md#createforms1) | **POST** /rest/v1/form/batch | Create a batch of forms
*FormApi* | [**deleteFormTemplate**](docs/FormApi.md#deleteformtemplate) | **DELETE** /rest/v2/form/template/{formTemplateId} | Delete a form template
*FormApi* | [**deleteFormTemplate1**](docs/FormApi.md#deleteformtemplate1) | **DELETE** /rest/v1/form/template/{formTemplateId} | Delete a form template
*FormApi* | [**deleteForms**](docs/FormApi.md#deleteforms) | **POST** /rest/v2/form/delete/batch | Delete forms.
*FormApi* | [**deleteForms1**](docs/FormApi.md#deleteforms1) | **DELETE** /rest/v1/form/{formIds} | Delete forms.
*FormApi* | [**findFormTemplates**](docs/FormApi.md#findformtemplates) | **GET** /rest/v1/form/template | Gets all form templates for current user
*FormApi* | [**findFormTemplatesBySpeciality**](docs/FormApi.md#findformtemplatesbyspeciality) | **GET** /rest/v1/form/template/bySpecialty/{specialityCode} | Gets all form templates
*FormApi* | [**findFormsByHCPartyPatientForeignKeys**](docs/FormApi.md#findformsbyhcpartypatientforeignkeys) | **GET** /rest/v1/form/byHcPartySecretForeignKeys | List forms found By Healthcare Party and secret foreign keys.
*FormApi* | [**findFormsDelegationsStubsByHCPartyPatientForeignKeys**](docs/FormApi.md#findformsdelegationsstubsbyhcpartypatientforeignkeys) | **GET** /rest/v1/form/byHcPartySecretForeignKeys/delegations | List form stubs found By Healthcare Party and secret foreign keys.
*FormApi* | [**getChildrenForms**](docs/FormApi.md#getchildrenforms) | **GET** /rest/v2/form/childrenOf/{formId}/{hcPartyId} | Get a list of forms by parents ids
*FormApi* | [**getChildrenForms1**](docs/FormApi.md#getchildrenforms1) | **GET** /rest/v1/form/childrenOf/{formId}/{hcPartyId} | Get a list of forms by ids
*FormApi* | [**getForm**](docs/FormApi.md#getform) | **GET** /rest/v2/form/{formId} | Gets a form
*FormApi* | [**getForm1**](docs/FormApi.md#getform1) | **GET** /rest/v1/form/{formId} | Gets a form
*FormApi* | [**getFormByLogicalUuid**](docs/FormApi.md#getformbylogicaluuid) | **GET** /rest/v1/form/logicalUuid/{logicalUuid} | Gets the most recent form with the given logicalUuid
*FormApi* | [**getFormByUniqueId**](docs/FormApi.md#getformbyuniqueid) | **GET** /rest/v1/form/uniqueId/{uniqueId} | Gets the most recent form with the given uniqueId
*FormApi* | [**getFormTemplate**](docs/FormApi.md#getformtemplate) | **GET** /rest/v2/form/template/{formTemplateId} | Gets a form template by guid
*FormApi* | [**getFormTemplate1**](docs/FormApi.md#getformtemplate1) | **GET** /rest/v1/form/template/{formTemplateId} | Gets a form template by guid
*FormApi* | [**getFormTemplates**](docs/FormApi.md#getformtemplates) | **GET** /rest/v2/form/template | Gets all form templates for current user
*FormApi* | [**getFormTemplatesByGuid**](docs/FormApi.md#getformtemplatesbyguid) | **GET** /rest/v2/form/template/{specialityCode}/guid/{formTemplateGuid} | Gets a form template
*FormApi* | [**getFormTemplatesByGuid1**](docs/FormApi.md#getformtemplatesbyguid1) | **GET** /rest/v1/form/template/{specialityCode}/guid/{formTemplateGuid} | Gets a form template
*FormApi* | [**getForms**](docs/FormApi.md#getforms) | **POST** /rest/v2/form/byIds | Get a list of forms by ids
*FormApi* | [**getForms1**](docs/FormApi.md#getforms1) | **POST** /rest/v1/form/byIds | Get a list of forms by ids
*FormApi* | [**getFormsByLogicalUuid**](docs/FormApi.md#getformsbylogicaluuid) | **GET** /rest/v1/form/all/logicalUuid/{logicalUuid} | Gets all forms with given logicalUuid
*FormApi* | [**getFormsByUniqueId**](docs/FormApi.md#getformsbyuniqueid) | **GET** /rest/v1/form/all/uniqueId/{uniqueId} | Gets all forms by uniqueId
*FormApi* | [**listFormTemplatesBySpeciality**](docs/FormApi.md#listformtemplatesbyspeciality) | **GET** /rest/v2/form/template/bySpecialty/{specialityCode} | Gets all form templates
*FormApi* | [**listFormsByHCPartyAndPatientForeignKeys**](docs/FormApi.md#listformsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/form/byHcPartySecretForeignKeys | List forms found By Healthcare Party and secret foreign keys.
*FormApi* | [**listFormsDelegationsStubsByHCPartyAndPatientForeignKeys**](docs/FormApi.md#listformsdelegationsstubsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/form/byHcPartySecretForeignKeys/delegations | List form stubs found By Healthcare Party and secret foreign keys.
*FormApi* | [**modifyForm**](docs/FormApi.md#modifyform) | **PUT** /rest/v2/form | Modify a form
*FormApi* | [**modifyForm1**](docs/FormApi.md#modifyform1) | **PUT** /rest/v1/form | Modify a form
*FormApi* | [**modifyForms**](docs/FormApi.md#modifyforms) | **PUT** /rest/v2/form/batch | Modify a batch of forms
*FormApi* | [**modifyForms1**](docs/FormApi.md#modifyforms1) | **PUT** /rest/v1/form/batch | Modify a batch of forms
*FormApi* | [**newFormDelegations**](docs/FormApi.md#newformdelegations) | **POST** /rest/v2/form/delegate/{formId} | Delegates a form to a healthcare party
*FormApi* | [**newFormDelegations1**](docs/FormApi.md#newformdelegations1) | **POST** /rest/v1/form/delegate/{formId} | Delegates a form to a healthcare party
*FormApi* | [**setFormsDelegations**](docs/FormApi.md#setformsdelegations) | **POST** /rest/v2/form/delegations | Update delegations in form.
*FormApi* | [**setFormsDelegations1**](docs/FormApi.md#setformsdelegations1) | **POST** /rest/v1/form/delegations | Update delegations in form.
*FormApi* | [**setTemplateAttachmentMulti**](docs/FormApi.md#settemplateattachmentmulti) | **PUT** /rest/v2/form/template/{formTemplateId}/attachment/multipart | Update a form template's layout
*FormApi* | [**setTemplateAttachmentMulti1**](docs/FormApi.md#settemplateattachmentmulti1) | **PUT** /rest/v1/form/template/{formTemplateId}/attachment/multipart | Update a form template's layout
*FormApi* | [**updateFormTemplate**](docs/FormApi.md#updateformtemplate) | **PUT** /rest/v2/form/template/{formTemplateId} | Modify a form template with the current user
*FormApi* | [**updateFormTemplate1**](docs/FormApi.md#updateformtemplate1) | **PUT** /rest/v1/form/template/{formTemplateId} | Modify a form template with the current user
*FrontendmigrationApi* | [**createFrontEndMigration**](docs/FrontendmigrationApi.md#createfrontendmigration) | **POST** /rest/v2/frontendmigration | Creates a front end migration
*FrontendmigrationApi* | [**createFrontEndMigration1**](docs/FrontendmigrationApi.md#createfrontendmigration1) | **POST** /rest/v1/frontendmigration | Creates a front end migration
*FrontendmigrationApi* | [**deleteFrontEndMigration**](docs/FrontendmigrationApi.md#deletefrontendmigration) | **DELETE** /rest/v2/frontendmigration/{frontEndMigrationId} | Deletes a front end migration
*FrontendmigrationApi* | [**deleteFrontEndMigration1**](docs/FrontendmigrationApi.md#deletefrontendmigration1) | **DELETE** /rest/v1/frontendmigration/{frontEndMigrationId} | Deletes a front end migration
*FrontendmigrationApi* | [**getFrontEndMigration**](docs/FrontendmigrationApi.md#getfrontendmigration) | **GET** /rest/v2/frontendmigration/{frontEndMigrationId} | Gets a front end migration
*FrontendmigrationApi* | [**getFrontEndMigration1**](docs/FrontendmigrationApi.md#getfrontendmigration1) | **GET** /rest/v1/frontendmigration/{frontEndMigrationId} | Gets a front end migration
*FrontendmigrationApi* | [**getFrontEndMigrationByName**](docs/FrontendmigrationApi.md#getfrontendmigrationbyname) | **GET** /rest/v2/frontendmigration/byName/{frontEndMigrationName} | Gets an front end migration
*FrontendmigrationApi* | [**getFrontEndMigrationByName1**](docs/FrontendmigrationApi.md#getfrontendmigrationbyname1) | **GET** /rest/v1/frontendmigration/byName/{frontEndMigrationName} | Gets an front end migration
*FrontendmigrationApi* | [**getFrontEndMigrations**](docs/FrontendmigrationApi.md#getfrontendmigrations) | **GET** /rest/v2/frontendmigration | Gets a front end migration
*FrontendmigrationApi* | [**getFrontEndMigrations1**](docs/FrontendmigrationApi.md#getfrontendmigrations1) | **GET** /rest/v1/frontendmigration | Gets a front end migration
*FrontendmigrationApi* | [**modifyFrontEndMigration**](docs/FrontendmigrationApi.md#modifyfrontendmigration) | **PUT** /rest/v2/frontendmigration | Modifies a front end migration
*FrontendmigrationApi* | [**modifyFrontEndMigration1**](docs/FrontendmigrationApi.md#modifyfrontendmigration1) | **PUT** /rest/v1/frontendmigration | Modifies a front end migration
*GroupApi* | [**createGroup**](docs/GroupApi.md#creategroup) | **POST** /rest/v1/group/{id} | Create a group
*GroupApi* | [**getGroup**](docs/GroupApi.md#getgroup) | **GET** /rest/v1/group/{id} | Get a group by id
*GroupApi* | [**getReplicationInfo2**](docs/GroupApi.md#getreplicationinfo2) | **GET** /rest/v1/group/{id}/r | Get index info
*GroupApi* | [**initDesignDocs**](docs/GroupApi.md#initdesigndocs) | **PUT** /rest/v1/group/{id}/dd | Init design docs
*GroupApi* | [**listGroups**](docs/GroupApi.md#listgroups) | **GET** /rest/v1/group | List groups
*GroupApi* | [**modifyGroupName**](docs/GroupApi.md#modifygroupname) | **PUT** /rest/v1/group/{id}/name/{name} | Update group name
*GroupApi* | [**modifyGroupProperties**](docs/GroupApi.md#modifygroupproperties) | **PUT** /rest/v1/group/{id}/properties | Update group properties
*GroupApi* | [**registerNewGroupAdministrator**](docs/GroupApi.md#registernewgroupadministrator) | **POST** /rest/v1/group/register/trial | Create a group
*GroupApi* | [**resetStorage**](docs/GroupApi.md#resetstorage) | **POST** /rest/v1/group/{id}/reset/storage | Reset storage for group
*GroupApi* | [**setGroupPassword**](docs/GroupApi.md#setgrouppassword) | **PUT** /rest/v1/group/{id}/password | Set group password
*GroupApi* | [**solveConflicts**](docs/GroupApi.md#solveconflicts) | **POST** /rest/v1/group/{id}/conflicts | Solve conflicts for group
*HcpartyApi* | [**createHealthcareParty**](docs/HcpartyApi.md#createhealthcareparty) | **POST** /rest/v2/hcparty | Create a healthcare party
*HcpartyApi* | [**createHealthcareParty1**](docs/HcpartyApi.md#createhealthcareparty1) | **POST** /rest/v1/hcparty | Create a healthcare party
*HcpartyApi* | [**createHealthcarePartyInGroup**](docs/HcpartyApi.md#createhealthcarepartyingroup) | **POST** /rest/v2/hcparty/inGroup/{groupId} | Create a healthcare party
*HcpartyApi* | [**createHealthcarePartyInGroup1**](docs/HcpartyApi.md#createhealthcarepartyingroup1) | **POST** /rest/v1/hcparty/inGroup/{groupId} | Create a healthcare party
*HcpartyApi* | [**deleteHealthcareParties**](docs/HcpartyApi.md#deletehealthcareparties) | **POST** /rest/v2/hcparty/delete/batch | Delete healthcare parties
*HcpartyApi* | [**deleteHealthcareParties1**](docs/HcpartyApi.md#deletehealthcareparties1) | **DELETE** /rest/v1/hcparty/{healthcarePartyIds} | Delete a healthcare party
*HcpartyApi* | [**deleteHealthcarePartiesInGroup**](docs/HcpartyApi.md#deletehealthcarepartiesingroup) | **POST** /rest/v2/hcparty/delete/batch/inGroup/{groupId} | Delete a healthcare party
*HcpartyApi* | [**deleteHealthcarePartiesInGroup1**](docs/HcpartyApi.md#deletehealthcarepartiesingroup1) | **DELETE** /rest/v1/hcparty/inGroup/{groupId}/{healthcarePartyIds} | Delete a healthcare party
*HcpartyApi* | [**findByName**](docs/HcpartyApi.md#findbyname) | **GET** /rest/v1/hcparty/byName | Find healthcare parties by name with(out) pagination
*HcpartyApi* | [**findBySpecialityAndPostCode**](docs/HcpartyApi.md#findbyspecialityandpostcode) | **GET** /rest/v1/hcparty/bySpecialityAndPostCode/{type}/{spec}/{firstCode}/to/{lastCode} | Find healthcare parties by name with(out) pagination
*HcpartyApi* | [**findBySsinOrNihii**](docs/HcpartyApi.md#findbyssinornihii) | **GET** /rest/v1/hcparty/byNihiiOrSsin/{searchValue} | Find healthcare parties by nihii or ssin with(out) pagination
*HcpartyApi* | [**findHealthcarePartiesBy**](docs/HcpartyApi.md#findhealthcarepartiesby) | **GET** /rest/v2/hcparty | List healthcare parties with(out) pagination
*HcpartyApi* | [**findHealthcarePartiesByName**](docs/HcpartyApi.md#findhealthcarepartiesbyname) | **GET** /rest/v2/hcparty/byName | Find healthcare parties by name with(out) pagination
*HcpartyApi* | [**findHealthcarePartiesBySpecialityAndPostCode**](docs/HcpartyApi.md#findhealthcarepartiesbyspecialityandpostcode) | **GET** /rest/v2/hcparty/bySpecialityAndPostCode/{type}/{spec}/{firstCode}/to/{lastCode} | Find healthcare parties by name with(out) pagination
*HcpartyApi* | [**findHealthcarePartiesBySsinOrNihii**](docs/HcpartyApi.md#findhealthcarepartiesbyssinornihii) | **GET** /rest/v2/hcparty/byNihiiOrSsin/{searchValue} | Find healthcare parties by nihii or ssin with(out) pagination
*HcpartyApi* | [**getCurrentHealthcareParty**](docs/HcpartyApi.md#getcurrenthealthcareparty) | **GET** /rest/v2/hcparty/current | Get the current healthcare party if logged in.
*HcpartyApi* | [**getCurrentHealthcareParty1**](docs/HcpartyApi.md#getcurrenthealthcareparty1) | **GET** /rest/v1/hcparty/current | Get the current healthcare party if logged in.
*HcpartyApi* | [**getHcPartyKeysForDelegate**](docs/HcpartyApi.md#gethcpartykeysfordelegate) | **GET** /rest/v2/hcparty/byKeys/{healthcarePartyId} | Get the HcParty encrypted AES keys indexed by owner
*HcpartyApi* | [**getHcPartyKeysForDelegate1**](docs/HcpartyApi.md#gethcpartykeysfordelegate1) | **GET** /rest/v1/hcparty/{healthcarePartyId}/keys | Get the HcParty encrypted AES keys indexed by owner
*HcpartyApi* | [**getHealthcareParties**](docs/HcpartyApi.md#gethealthcareparties) | **POST** /rest/v2/hcparty/byIds | Get healthcareParties by their IDs
*HcpartyApi* | [**getHealthcareParties1**](docs/HcpartyApi.md#gethealthcareparties1) | **GET** /rest/v1/hcparty/byIds/{healthcarePartyIds} | Get healthcareParties by their IDs
*HcpartyApi* | [**getHealthcarePartiesByParentId**](docs/HcpartyApi.md#gethealthcarepartiesbyparentid) | **GET** /rest/v1/hcparty/{parentId}/children | Find children of an healthcare parties
*HcpartyApi* | [**getHealthcarePartiesInGroup**](docs/HcpartyApi.md#gethealthcarepartiesingroup) | **POST** /rest/v1/hcparty/inGroup/{groupId}/byIds | Get healthcareParties by their IDs
*HcpartyApi* | [**getHealthcareParty**](docs/HcpartyApi.md#gethealthcareparty) | **GET** /rest/v2/hcparty/{healthcarePartyId} | Get a healthcareParty by his ID
*HcpartyApi* | [**getHealthcareParty1**](docs/HcpartyApi.md#gethealthcareparty1) | **GET** /rest/v1/hcparty/{healthcarePartyId} | Get a healthcareParty by his ID
*HcpartyApi* | [**getPublicKey**](docs/HcpartyApi.md#getpublickey) | **GET** /rest/v2/hcparty/{healthcarePartyId}/publicKey | Get public key of a healthcare party
*HcpartyApi* | [**getPublicKey1**](docs/HcpartyApi.md#getpublickey1) | **GET** /rest/v1/hcparty/{healthcarePartyId}/publicKey | Get public key of a healthcare party
*HcpartyApi* | [**listByName**](docs/HcpartyApi.md#listbyname) | **GET** /rest/v1/hcparty/byNameStrict/{name} | Find healthcare parties by name with(out) pagination
*HcpartyApi* | [**listHealthcareParties**](docs/HcpartyApi.md#listhealthcareparties) | **GET** /rest/v1/hcparty | List healthcare parties with(out) pagination
*HcpartyApi* | [**listHealthcarePartiesByName**](docs/HcpartyApi.md#listhealthcarepartiesbyname) | **GET** /rest/v2/hcparty/byNameStrict/{name} | Find healthcare parties by name with(out) pagination
*HcpartyApi* | [**listHealthcarePartiesByParentId**](docs/HcpartyApi.md#listhealthcarepartiesbyparentid) | **GET** /rest/v2/hcparty/{parentId}/children | Find children of an healthcare parties
*HcpartyApi* | [**modifyHealthcareParty**](docs/HcpartyApi.md#modifyhealthcareparty) | **PUT** /rest/v2/hcparty | Modify a Healthcare Party.
*HcpartyApi* | [**modifyHealthcareParty1**](docs/HcpartyApi.md#modifyhealthcareparty1) | **PUT** /rest/v1/hcparty | Modify a Healthcare Party.
*HcpartyApi* | [**modifyHealthcarePartyInGroup**](docs/HcpartyApi.md#modifyhealthcarepartyingroup) | **PUT** /rest/v2/hcparty/inGroup/{groupId} | Modify a Healthcare Party.
*HcpartyApi* | [**modifyHealthcarePartyInGroup1**](docs/HcpartyApi.md#modifyhealthcarepartyingroup1) | **PUT** /rest/v1/hcparty/inGroup/{groupId} | Modify a Healthcare Party.
*HelementApi* | [**createHealthElement**](docs/HelementApi.md#createhealthelement) | **POST** /rest/v2/helement | Create a health element with the current user
*HelementApi* | [**createHealthElement1**](docs/HelementApi.md#createhealthelement1) | **POST** /rest/v1/helement | Create a healthcare element with the current user
*HelementApi* | [**createHealthElements**](docs/HelementApi.md#createhealthelements) | **POST** /rest/v2/helement/batch | Create a batch of healthcare elements
*HelementApi* | [**createHealthElements1**](docs/HelementApi.md#createhealthelements1) | **POST** /rest/v1/helement/batch | Create a batch of healthcare elements
*HelementApi* | [**deleteHealthElements**](docs/HelementApi.md#deletehealthelements) | **DELETE** /rest/v2/helement/delete/batch | Delete health elements.
*HelementApi* | [**deleteHealthElements1**](docs/HelementApi.md#deletehealthelements1) | **DELETE** /rest/v1/helement/{healthElementIds} | Delete healthcare elements.
*HelementApi* | [**filterHealthElementsBy**](docs/HelementApi.md#filterhealthelementsby) | **POST** /rest/v2/helement/filter | Filter health elements for the current user (HcParty)
*HelementApi* | [**filterHealthElementsBy1**](docs/HelementApi.md#filterhealthelementsby1) | **POST** /rest/v1/helement/filter | Filter healthcare elements for the current user (HcParty)
*HelementApi* | [**findHealthElementsByHCPartyPatientForeignKeys**](docs/HelementApi.md#findhealthelementsbyhcpartypatientforeignkeys) | **GET** /rest/v1/helement/byHcPartySecretForeignKeys | List healthcare elements found By Healthcare Party and secret foreign keyelementIds.
*HelementApi* | [**findHealthElementsDelegationsStubsByHCPartyPatientForeignKeys**](docs/HelementApi.md#findhealthelementsdelegationsstubsbyhcpartypatientforeignkeys) | **GET** /rest/v1/helement/byHcPartySecretForeignKeys/delegations | List helement stubs found By Healthcare Party and secret foreign keys.
*HelementApi* | [**getHealthElement**](docs/HelementApi.md#gethealthelement) | **GET** /rest/v2/helement/{healthElementId} | Get a health element
*HelementApi* | [**getHealthElement1**](docs/HelementApi.md#gethealthelement1) | **GET** /rest/v1/helement/{healthElementId} | Get a healthcare element
*HelementApi* | [**listHealthElementsByHCPartyAndPatientForeignKeys**](docs/HelementApi.md#listhealthelementsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/helement/byHcPartySecretForeignKeys | List health elements found By Healthcare Party and secret foreign keyelementIds.
*HelementApi* | [**listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys**](docs/HelementApi.md#listhealthelementsdelegationsstubsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/helement/byHcPartySecretForeignKeys/delegations | List helement stubs found By Healthcare Party and secret foreign keys.
*HelementApi* | [**modifyHealthElement**](docs/HelementApi.md#modifyhealthelement) | **PUT** /rest/v2/helement | Modify a health element
*HelementApi* | [**modifyHealthElement1**](docs/HelementApi.md#modifyhealthelement1) | **PUT** /rest/v1/helement | Modify a healthcare element
*HelementApi* | [**modifyHealthElements**](docs/HelementApi.md#modifyhealthelements) | **PUT** /rest/v2/helement/batch | Modify a batch of health elements
*HelementApi* | [**modifyHealthElements1**](docs/HelementApi.md#modifyhealthelements1) | **PUT** /rest/v1/helement/batch | Modify a batch of healthcare elements
*HelementApi* | [**newHealthElementDelegations**](docs/HelementApi.md#newhealthelementdelegations) | **POST** /rest/v2/helement/{healthElementId}/delegate | Delegates a health element to a healthcare party
*HelementApi* | [**newHealthElementDelegations1**](docs/HelementApi.md#newhealthelementdelegations1) | **POST** /rest/v1/helement/{healthElementId}/delegate | Delegates a healthcare element to a healthcare party
*HelementApi* | [**setHealthElementsDelegations**](docs/HelementApi.md#sethealthelementsdelegations) | **POST** /rest/v2/helement/delegations | Update delegations in healthElements.
*HelementApi* | [**setHealthElementsDelegations1**](docs/HelementApi.md#sethealthelementsdelegations1) | **POST** /rest/v1/helement/delegations | Update delegations in healthElements.
*IcureApi* | [**getIndexingInfo**](docs/IcureApi.md#getindexinginfo) | **GET** /rest/v2/icure/i | Get index info
*IcureApi* | [**getIndexingInfo1**](docs/IcureApi.md#getindexinginfo1) | **GET** /rest/v1/icure/i | Get index info
*IcureApi* | [**getProcessInfo**](docs/IcureApi.md#getprocessinfo) | **GET** /rest/v2/icure/p | Get process info
*IcureApi* | [**getProcessInfo1**](docs/IcureApi.md#getprocessinfo1) | **GET** /rest/v1/icure/p | Get process info
*IcureApi* | [**getReplicationInfo**](docs/IcureApi.md#getreplicationinfo) | **GET** /rest/v2/icure/r | Get replication info
*IcureApi* | [**getReplicationInfo1**](docs/IcureApi.md#getreplicationinfo1) | **GET** /rest/v1/icure/r | Get replication info
*IcureApi* | [**getReplicatorInfo**](docs/IcureApi.md#getreplicatorinfo) | **GET** /rest/v2/icure/r/{id} | Get replication info
*IcureApi* | [**getReplicatorInfo1**](docs/IcureApi.md#getreplicatorinfo1) | **GET** /rest/v1/icure/r/{id} | Get replication info
*IcureApi* | [**getVersion**](docs/IcureApi.md#getversion) | **GET** /rest/v2/icure/v | Get version
*IcureApi* | [**getVersion1**](docs/IcureApi.md#getversion1) | **GET** /rest/v1/icure/v | Get version
*IcureApi* | [**isReady**](docs/IcureApi.md#isready) | **GET** /rest/v2/icure/ok | Check if a user exists
*IcureApi* | [**isReady1**](docs/IcureApi.md#isready1) | **GET** /rest/v1/icure/ok | Check if a user exists
*IcureApi* | [**resolveContactsConflicts**](docs/IcureApi.md#resolvecontactsconflicts) | **POST** /rest/v2/icure/conflicts/contact | Resolve contacts conflicts
*IcureApi* | [**resolveContactsConflicts1**](docs/IcureApi.md#resolvecontactsconflicts1) | **POST** /rest/v1/icure/conflicts/contact | Resolve contacts conflicts
*IcureApi* | [**resolveDocumentsConflicts**](docs/IcureApi.md#resolvedocumentsconflicts) | **POST** /rest/v2/icure/conflicts/document | resolve documents conflicts
*IcureApi* | [**resolveDocumentsConflicts1**](docs/IcureApi.md#resolvedocumentsconflicts1) | **POST** /rest/v1/icure/conflicts/document | resolve documents conflicts
*IcureApi* | [**resolveFormsConflicts**](docs/IcureApi.md#resolveformsconflicts) | **POST** /rest/v2/icure/conflicts/form | resolve forms conflicts
*IcureApi* | [**resolveFormsConflicts1**](docs/IcureApi.md#resolveformsconflicts1) | **POST** /rest/v1/icure/conflicts/form | resolve forms conflicts
*IcureApi* | [**resolveHealthElementsConflicts**](docs/IcureApi.md#resolvehealthelementsconflicts) | **POST** /rest/v2/icure/conflicts/healthelement | resolve healthcare elements conflicts
*IcureApi* | [**resolveHealthElementsConflicts1**](docs/IcureApi.md#resolvehealthelementsconflicts1) | **POST** /rest/v1/icure/conflicts/healthelement | resolve healthcare elements conflicts
*IcureApi* | [**resolveInvoicesConflicts**](docs/IcureApi.md#resolveinvoicesconflicts) | **POST** /rest/v2/icure/conflicts/invoice | resolve invoices conflicts
*IcureApi* | [**resolveInvoicesConflicts1**](docs/IcureApi.md#resolveinvoicesconflicts1) | **POST** /rest/v1/icure/conflicts/invoice | resolve invoices conflicts
*IcureApi* | [**resolveMessagesConflicts**](docs/IcureApi.md#resolvemessagesconflicts) | **POST** /rest/v2/icure/conflicts/message | resolve messages conflicts
*IcureApi* | [**resolveMessagesConflicts1**](docs/IcureApi.md#resolvemessagesconflicts1) | **POST** /rest/v1/icure/conflicts/message | resolve messages conflicts
*IcureApi* | [**resolvePatientsConflicts**](docs/IcureApi.md#resolvepatientsconflicts) | **POST** /rest/v2/icure/conflicts/patient | Resolve patients conflicts
*IcureApi* | [**resolvePatientsConflicts1**](docs/IcureApi.md#resolvepatientsconflicts1) | **POST** /rest/v1/icure/conflicts/patient | Resolve patients conflicts
*IcureApi* | [**updateDesignDoc**](docs/IcureApi.md#updatedesigndoc) | **POST** /rest/v2/icure/dd/{entityName} | Force update design doc
*IcureApi* | [**updateDesignDoc1**](docs/IcureApi.md#updatedesigndoc1) | **POST** /rest/v1/icure/dd/{entityName} | Force update design doc
*InsuranceApi* | [**createInsurance**](docs/InsuranceApi.md#createinsurance) | **POST** /rest/v2/insurance | Creates an insurance
*InsuranceApi* | [**createInsurance1**](docs/InsuranceApi.md#createinsurance1) | **POST** /rest/v1/insurance | Creates an insurance
*InsuranceApi* | [**deleteInsurance**](docs/InsuranceApi.md#deleteinsurance) | **DELETE** /rest/v2/insurance/{insuranceId} | Deletes an insurance
*InsuranceApi* | [**deleteInsurance1**](docs/InsuranceApi.md#deleteinsurance1) | **DELETE** /rest/v1/insurance/{insuranceId} | Deletes an insurance
*InsuranceApi* | [**getInsurance**](docs/InsuranceApi.md#getinsurance) | **GET** /rest/v2/insurance/{insuranceId} | Gets an insurance
*InsuranceApi* | [**getInsurance1**](docs/InsuranceApi.md#getinsurance1) | **GET** /rest/v1/insurance/{insuranceId} | Gets an insurance
*InsuranceApi* | [**getInsurances**](docs/InsuranceApi.md#getinsurances) | **POST** /rest/v2/insurance/byIds | Gets insurances by id
*InsuranceApi* | [**getInsurances1**](docs/InsuranceApi.md#getinsurances1) | **POST** /rest/v1/insurance/byIds | Gets insurances by id
*InsuranceApi* | [**listInsurancesByCode**](docs/InsuranceApi.md#listinsurancesbycode) | **GET** /rest/v2/insurance/byCode/{insuranceCode} | Gets an insurance
*InsuranceApi* | [**listInsurancesByCode1**](docs/InsuranceApi.md#listinsurancesbycode1) | **GET** /rest/v1/insurance/byCode/{insuranceCode} | Gets an insurance
*InsuranceApi* | [**listInsurancesByName**](docs/InsuranceApi.md#listinsurancesbyname) | **GET** /rest/v2/insurance/byName/{insuranceName} | Gets an insurance
*InsuranceApi* | [**listInsurancesByName1**](docs/InsuranceApi.md#listinsurancesbyname1) | **GET** /rest/v1/insurance/byName/{insuranceName} | Gets an insurance
*InsuranceApi* | [**modifyInsurance**](docs/InsuranceApi.md#modifyinsurance) | **PUT** /rest/v2/insurance | Modifies an insurance
*InsuranceApi* | [**modifyInsurance1**](docs/InsuranceApi.md#modifyinsurance1) | **PUT** /rest/v1/insurance | Modifies an insurance
*InvoiceApi* | [**appendCodes**](docs/InvoiceApi.md#appendcodes) | **POST** /rest/v2/invoice/byauthor/{userId}/append/{type}/{sentMediumType} | Gets all invoices for author at date
*InvoiceApi* | [**appendCodes1**](docs/InvoiceApi.md#appendcodes1) | **POST** /rest/v1/invoice/byauthor/{userId}/append/{type}/{sentMediumType} | Gets all invoices for author at date
*InvoiceApi* | [**createInvoice**](docs/InvoiceApi.md#createinvoice) | **POST** /rest/v2/invoice | Creates an invoice
*InvoiceApi* | [**createInvoice1**](docs/InvoiceApi.md#createinvoice1) | **POST** /rest/v1/invoice | Creates an invoice
*InvoiceApi* | [**createInvoices**](docs/InvoiceApi.md#createinvoices) | **POST** /rest/v2/invoice/batch | Create a batch of invoices
*InvoiceApi* | [**createInvoices1**](docs/InvoiceApi.md#createinvoices1) | **POST** /rest/v1/invoice/batch | Create a batch of invoices
*InvoiceApi* | [**deleteInvoice**](docs/InvoiceApi.md#deleteinvoice) | **DELETE** /rest/v2/invoice/{invoiceId} | Deletes an invoice
*InvoiceApi* | [**deleteInvoice1**](docs/InvoiceApi.md#deleteinvoice1) | **DELETE** /rest/v1/invoice/{invoiceId} | Deletes an invoice
*InvoiceApi* | [**filterInvoicesBy**](docs/InvoiceApi.md#filterinvoicesby) | **POST** /rest/v2/invoice/filter | Filter invoices for the current user (HcParty)
*InvoiceApi* | [**filterInvoicesBy1**](docs/InvoiceApi.md#filterinvoicesby1) | **POST** /rest/v1/invoice/filter | Filter invoices for the current user (HcParty)
*InvoiceApi* | [**findByAuthor**](docs/InvoiceApi.md#findbyauthor) | **GET** /rest/v1/invoice/byauthor/{hcPartyId} | Gets all invoices for author at date
*InvoiceApi* | [**findInvoicesByHCPartyPatientForeignKeys**](docs/InvoiceApi.md#findinvoicesbyhcpartypatientforeignkeys) | **GET** /rest/v1/invoice/byHcPartySecretForeignKeys | List invoices found By Healthcare Party and secret foreign patient keys.
*InvoiceApi* | [**findInvoicesDelegationsStubsByHCPartyPatientForeignKeys**](docs/InvoiceApi.md#findinvoicesdelegationsstubsbyhcpartypatientforeignkeys) | **GET** /rest/v1/invoice/byHcPartySecretForeignKeys/delegations | List helement stubs found By Healthcare Party and secret foreign keys.
*InvoiceApi* | [**getInvoice**](docs/InvoiceApi.md#getinvoice) | **GET** /rest/v2/invoice/{invoiceId} | Gets an invoice
*InvoiceApi* | [**getInvoice1**](docs/InvoiceApi.md#getinvoice1) | **GET** /rest/v1/invoice/{invoiceId} | Gets an invoice
*InvoiceApi* | [**getInvoices**](docs/InvoiceApi.md#getinvoices) | **POST** /rest/v2/invoice/byIds | Gets an invoice
*InvoiceApi* | [**getInvoices1**](docs/InvoiceApi.md#getinvoices1) | **POST** /rest/v1/invoice/byIds | Gets an invoice
*InvoiceApi* | [**getTarificationsCodesOccurences**](docs/InvoiceApi.md#gettarificationscodesoccurences) | **GET** /rest/v2/invoice/codes/{minOccurences} | Get the list of all used tarifications frequencies in invoices
*InvoiceApi* | [**getTarificationsCodesOccurences1**](docs/InvoiceApi.md#gettarificationscodesoccurences1) | **GET** /rest/v1/invoice/codes/{minOccurences} | Get the list of all used tarifications frequencies in invoices
*InvoiceApi* | [**listAllHcpsByStatus**](docs/InvoiceApi.md#listallhcpsbystatus) | **POST** /rest/v2/invoice/allHcpsByStatus/{status} | Gets all invoices per status
*InvoiceApi* | [**listAllHcpsByStatus1**](docs/InvoiceApi.md#listallhcpsbystatus1) | **POST** /rest/v1/invoice/allHcpsByStatus/{status} | Gets all invoices per status
*InvoiceApi* | [**listByContactIds**](docs/InvoiceApi.md#listbycontactids) | **POST** /rest/v1/invoice/byCtcts | Gets all invoices for author at date
*InvoiceApi* | [**listByHcPartyGroupId**](docs/InvoiceApi.md#listbyhcpartygroupid) | **GET** /rest/v1/invoice/byHcPartyGroupId/{hcPartyId}/{groupId} | List invoices by groupId
*InvoiceApi* | [**listByHcPartySentMediumTypeInvoiceTypeSentDate**](docs/InvoiceApi.md#listbyhcpartysentmediumtypeinvoicetypesentdate) | **GET** /rest/v1/invoice/byHcParty/{hcPartyId}/mediumType/{sentMediumType}/invoiceType/{invoiceType}/sent/{sent} | List invoices by type, sent or unsent
*InvoiceApi* | [**listByHcpartySendingModeStatusDate**](docs/InvoiceApi.md#listbyhcpartysendingmodestatusdate) | **GET** /rest/v1/invoice/byHcpartySendingModeStatusDate/{hcPartyId} | Get all invoices by author, by sending mode, by status and by date
*InvoiceApi* | [**listByIds**](docs/InvoiceApi.md#listbyids) | **GET** /rest/v1/invoice/byIds/{invoiceIds} | Gets all invoices for author at date
*InvoiceApi* | [**listByRecipientsIds**](docs/InvoiceApi.md#listbyrecipientsids) | **GET** /rest/v1/invoice/to/{recipientIds} | Gets all invoices for author at date
*InvoiceApi* | [**listByServiceIds**](docs/InvoiceApi.md#listbyserviceids) | **GET** /rest/v1/invoice/byServiceIds/{serviceIds} | Gets all invoices for author at date
*InvoiceApi* | [**listInvoicesByAuthor**](docs/InvoiceApi.md#listinvoicesbyauthor) | **GET** /rest/v2/invoice/byauthor/{hcPartyId} | Gets all invoices for author at date
*InvoiceApi* | [**listInvoicesByContactIds**](docs/InvoiceApi.md#listinvoicesbycontactids) | **POST** /rest/v2/invoice/byContacts | Gets all invoices for author at date
*InvoiceApi* | [**listInvoicesByHCPartyAndPatientForeignKeys**](docs/InvoiceApi.md#listinvoicesbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/invoice/byHcPartySecretForeignKeys | List invoices found By Healthcare Party and secret foreign patient keys.
*InvoiceApi* | [**listInvoicesByHcPartyAndGroupId**](docs/InvoiceApi.md#listinvoicesbyhcpartyandgroupid) | **GET** /rest/v2/invoice/byHcPartyGroupId/{hcPartyId}/{groupId} | List invoices by groupId
*InvoiceApi* | [**listInvoicesByHcPartySentMediumTypeInvoiceTypeSentDate**](docs/InvoiceApi.md#listinvoicesbyhcpartysentmediumtypeinvoicetypesentdate) | **GET** /rest/v2/invoice/byHcParty/{hcPartyId}/mediumType/{sentMediumType}/invoiceType/{invoiceType}/sent/{sent} | List invoices by type, sent or unsent
*InvoiceApi* | [**listInvoicesByHcpartySendingModeStatusDate**](docs/InvoiceApi.md#listinvoicesbyhcpartysendingmodestatusdate) | **GET** /rest/v2/invoice/byHcpartySendingModeStatusDate/{hcPartyId} | Get all invoices by author, by sending mode, by status and by date
*InvoiceApi* | [**listInvoicesByIds**](docs/InvoiceApi.md#listinvoicesbyids) | **GET** /rest/v2/invoice/byIds/{invoiceIds} | Gets all invoices for author at date
*InvoiceApi* | [**listInvoicesByRecipientsIds**](docs/InvoiceApi.md#listinvoicesbyrecipientsids) | **GET** /rest/v2/invoice/to/{recipientIds} | Gets all invoices for author at date
*InvoiceApi* | [**listInvoicesByServiceIds**](docs/InvoiceApi.md#listinvoicesbyserviceids) | **GET** /rest/v2/invoice/byServiceIds/{serviceIds} | Gets all invoices for author at date
*InvoiceApi* | [**listInvoicesDelegationsStubsByHCPartyAndPatientForeignKeys**](docs/InvoiceApi.md#listinvoicesdelegationsstubsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/invoice/byHcPartySecretForeignKeys/delegations | List helement stubs found By Healthcare Party and secret foreign keys.
*InvoiceApi* | [**listToInsurances**](docs/InvoiceApi.md#listtoinsurances) | **GET** /rest/v2/invoice/toInsurances | Gets all invoices for author at date
*InvoiceApi* | [**listToInsurances1**](docs/InvoiceApi.md#listtoinsurances1) | **GET** /rest/v1/invoice/toInsurances | Gets all invoices for author at date
*InvoiceApi* | [**listToInsurancesUnsent**](docs/InvoiceApi.md#listtoinsurancesunsent) | **GET** /rest/v2/invoice/toInsurances/unsent | Gets all invoices for author at date
*InvoiceApi* | [**listToInsurancesUnsent1**](docs/InvoiceApi.md#listtoinsurancesunsent1) | **GET** /rest/v1/invoice/toInsurances/unsent | Gets all invoices for author at date
*InvoiceApi* | [**listToPatients**](docs/InvoiceApi.md#listtopatients) | **GET** /rest/v2/invoice/toPatients | Gets all invoices for author at date
*InvoiceApi* | [**listToPatients1**](docs/InvoiceApi.md#listtopatients1) | **GET** /rest/v1/invoice/toPatients | Gets all invoices for author at date
*InvoiceApi* | [**listToPatientsUnsent**](docs/InvoiceApi.md#listtopatientsunsent) | **GET** /rest/v2/invoice/toPatients/unsent | Gets all invoices for author at date
*InvoiceApi* | [**listToPatientsUnsent1**](docs/InvoiceApi.md#listtopatientsunsent1) | **GET** /rest/v1/invoice/toPatients/unsent | Gets all invoices for author at date
*InvoiceApi* | [**mergeTo**](docs/InvoiceApi.md#mergeto) | **POST** /rest/v2/invoice/mergeTo/{invoiceId} | Gets all invoices for author at date
*InvoiceApi* | [**mergeTo1**](docs/InvoiceApi.md#mergeto1) | **POST** /rest/v1/invoice/mergeTo/{invoiceId} | Gets all invoices for author at date
*InvoiceApi* | [**modifyInvoice**](docs/InvoiceApi.md#modifyinvoice) | **PUT** /rest/v2/invoice | Modifies an invoice
*InvoiceApi* | [**modifyInvoice1**](docs/InvoiceApi.md#modifyinvoice1) | **PUT** /rest/v1/invoice | Modifies an invoice
*InvoiceApi* | [**modifyInvoices**](docs/InvoiceApi.md#modifyinvoices) | **PUT** /rest/v2/invoice/batch | Modify a batch of invoices
*InvoiceApi* | [**modifyInvoices1**](docs/InvoiceApi.md#modifyinvoices1) | **PUT** /rest/v1/invoice/batch | Modify a batch of invoices
*InvoiceApi* | [**newInvoiceDelegations**](docs/InvoiceApi.md#newinvoicedelegations) | **PUT** /rest/v2/invoice/{invoiceId}/delegate | Adds a delegation to a invoice
*InvoiceApi* | [**newInvoiceDelegations1**](docs/InvoiceApi.md#newinvoicedelegations1) | **PUT** /rest/v1/invoice/{invoiceId}/delegate | Adds a delegation to a invoice
*InvoiceApi* | [**reassignInvoice**](docs/InvoiceApi.md#reassigninvoice) | **POST** /rest/v2/invoice/reassign | Modifies an invoice
*InvoiceApi* | [**reassignInvoice1**](docs/InvoiceApi.md#reassigninvoice1) | **POST** /rest/v1/invoice/reassign | Modifies an invoice
*InvoiceApi* | [**removeCodes**](docs/InvoiceApi.md#removecodes) | **POST** /rest/v2/invoice/byauthor/{userId}/service/{serviceId} | Remove an invoice of an user
*InvoiceApi* | [**removeCodes1**](docs/InvoiceApi.md#removecodes1) | **POST** /rest/v1/invoice/byauthor/{userId}/service/{serviceId} | Gets all invoices for author at date
*InvoiceApi* | [**setInvoicesDelegations**](docs/InvoiceApi.md#setinvoicesdelegations) | **POST** /rest/v2/invoice/delegations | Update delegations in healthElements.
*InvoiceApi* | [**setInvoicesDelegations1**](docs/InvoiceApi.md#setinvoicesdelegations1) | **POST** /rest/v1/invoice/delegations | Update delegations in healthElements.
*InvoiceApi* | [**validate**](docs/InvoiceApi.md#validate) | **POST** /rest/v2/invoice/validate/{invoiceId} | Gets all invoices for author at date
*InvoiceApi* | [**validate1**](docs/InvoiceApi.md#validate1) | **POST** /rest/v1/invoice/validate/{invoiceId} | Gets all invoices for author at date
*KeywordApi* | [**createKeyword**](docs/KeywordApi.md#createkeyword) | **POST** /rest/v2/keyword | Create a keyword with the current user
*KeywordApi* | [**createKeyword1**](docs/KeywordApi.md#createkeyword1) | **POST** /rest/v1/keyword | Create a keyword with the current user
*KeywordApi* | [**deleteKeywords**](docs/KeywordApi.md#deletekeywords) | **POST** /rest/v2/keyword/delete/batch | Delete keywords.
*KeywordApi* | [**deleteKeywords1**](docs/KeywordApi.md#deletekeywords1) | **DELETE** /rest/v1/keyword/{keywordIds} | Delete keywords.
*KeywordApi* | [**getKeyword**](docs/KeywordApi.md#getkeyword) | **GET** /rest/v2/keyword/{keywordId} | Get a keyword
*KeywordApi* | [**getKeyword1**](docs/KeywordApi.md#getkeyword1) | **GET** /rest/v1/keyword/{keywordId} | Get a keyword
*KeywordApi* | [**getKeywords**](docs/KeywordApi.md#getkeywords) | **GET** /rest/v2/keyword | Gets all keywords
*KeywordApi* | [**getKeywords1**](docs/KeywordApi.md#getkeywords1) | **GET** /rest/v1/keyword | Gets all keywords
*KeywordApi* | [**getKeywordsByUser**](docs/KeywordApi.md#getkeywordsbyuser) | **GET** /rest/v2/keyword/byUser/{userId} | Get keywords by user
*KeywordApi* | [**getKeywordsByUser1**](docs/KeywordApi.md#getkeywordsbyuser1) | **GET** /rest/v1/keyword/byUser/{userId} | Get keywords by user
*KeywordApi* | [**modifyKeyword**](docs/KeywordApi.md#modifykeyword) | **PUT** /rest/v2/keyword | Modify a keyword
*KeywordApi* | [**modifyKeyword1**](docs/KeywordApi.md#modifykeyword1) | **PUT** /rest/v1/keyword | Modify a keyword
*KmehrWsControllerApi* | [**generateDiaryNote10**](docs/KmehrWsControllerApi.md#generatediarynote10) | **PUT** /ws/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote11**](docs/KmehrWsControllerApi.md#generatediarynote11) | **HEAD** /ws/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote12**](docs/KmehrWsControllerApi.md#generatediarynote12) | **GET** /ws/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote13**](docs/KmehrWsControllerApi.md#generatediarynote13) | **PATCH** /ws/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote14**](docs/KmehrWsControllerApi.md#generatediarynote14) | **OPTIONS** /ws/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote15**](docs/KmehrWsControllerApi.md#generatediarynote15) | **DELETE** /ws/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote2**](docs/KmehrWsControllerApi.md#generatediarynote2) | **POST** /ws/v2/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote3**](docs/KmehrWsControllerApi.md#generatediarynote3) | **PUT** /ws/v2/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote4**](docs/KmehrWsControllerApi.md#generatediarynote4) | **HEAD** /ws/v2/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote5**](docs/KmehrWsControllerApi.md#generatediarynote5) | **GET** /ws/v2/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote6**](docs/KmehrWsControllerApi.md#generatediarynote6) | **PATCH** /ws/v2/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote7**](docs/KmehrWsControllerApi.md#generatediarynote7) | **OPTIONS** /ws/v2/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote8**](docs/KmehrWsControllerApi.md#generatediarynote8) | **DELETE** /ws/v2/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateDiaryNote9**](docs/KmehrWsControllerApi.md#generatediarynote9) | **POST** /ws/be_kmehr/generateDiaryNote | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport10**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport10) | **PUT** /ws/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport11**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport11) | **HEAD** /ws/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport12**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport12) | **GET** /ws/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport13**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport13) | **PATCH** /ws/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport14**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport14) | **OPTIONS** /ws/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport15**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport15) | **DELETE** /ws/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport2**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport2) | **POST** /ws/v2/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport3**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport3) | **PUT** /ws/v2/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport4**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport4) | **HEAD** /ws/v2/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport5**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport5) | **GET** /ws/v2/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport6**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport6) | **PATCH** /ws/v2/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport7**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport7) | **OPTIONS** /ws/v2/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport8**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport8) | **DELETE** /ws/v2/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateMedicationSchemeExport9**](docs/KmehrWsControllerApi.md#generatemedicationschemeexport9) | **POST** /ws/be_kmehr/generateMedicationScheme | 
*KmehrWsControllerApi* | [**generateSmfExport10**](docs/KmehrWsControllerApi.md#generatesmfexport10) | **PUT** /ws/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport11**](docs/KmehrWsControllerApi.md#generatesmfexport11) | **HEAD** /ws/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport12**](docs/KmehrWsControllerApi.md#generatesmfexport12) | **GET** /ws/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport13**](docs/KmehrWsControllerApi.md#generatesmfexport13) | **PATCH** /ws/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport14**](docs/KmehrWsControllerApi.md#generatesmfexport14) | **OPTIONS** /ws/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport15**](docs/KmehrWsControllerApi.md#generatesmfexport15) | **DELETE** /ws/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport2**](docs/KmehrWsControllerApi.md#generatesmfexport2) | **POST** /ws/v2/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport3**](docs/KmehrWsControllerApi.md#generatesmfexport3) | **PUT** /ws/v2/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport4**](docs/KmehrWsControllerApi.md#generatesmfexport4) | **HEAD** /ws/v2/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport5**](docs/KmehrWsControllerApi.md#generatesmfexport5) | **GET** /ws/v2/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport6**](docs/KmehrWsControllerApi.md#generatesmfexport6) | **PATCH** /ws/v2/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport7**](docs/KmehrWsControllerApi.md#generatesmfexport7) | **OPTIONS** /ws/v2/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport8**](docs/KmehrWsControllerApi.md#generatesmfexport8) | **DELETE** /ws/v2/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSmfExport9**](docs/KmehrWsControllerApi.md#generatesmfexport9) | **POST** /ws/be_kmehr/generateSmf | 
*KmehrWsControllerApi* | [**generateSumehr10**](docs/KmehrWsControllerApi.md#generatesumehr10) | **PUT** /ws/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr11**](docs/KmehrWsControllerApi.md#generatesumehr11) | **HEAD** /ws/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr12**](docs/KmehrWsControllerApi.md#generatesumehr12) | **GET** /ws/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr13**](docs/KmehrWsControllerApi.md#generatesumehr13) | **PATCH** /ws/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr14**](docs/KmehrWsControllerApi.md#generatesumehr14) | **OPTIONS** /ws/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr15**](docs/KmehrWsControllerApi.md#generatesumehr15) | **DELETE** /ws/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr2**](docs/KmehrWsControllerApi.md#generatesumehr2) | **POST** /ws/v2/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr3**](docs/KmehrWsControllerApi.md#generatesumehr3) | **PUT** /ws/v2/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr4**](docs/KmehrWsControllerApi.md#generatesumehr4) | **HEAD** /ws/v2/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr5**](docs/KmehrWsControllerApi.md#generatesumehr5) | **GET** /ws/v2/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr6**](docs/KmehrWsControllerApi.md#generatesumehr6) | **PATCH** /ws/v2/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr7**](docs/KmehrWsControllerApi.md#generatesumehr7) | **OPTIONS** /ws/v2/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr8**](docs/KmehrWsControllerApi.md#generatesumehr8) | **DELETE** /ws/v2/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehr9**](docs/KmehrWsControllerApi.md#generatesumehr9) | **POST** /ws/be_kmehr/generateSumehr | 
*KmehrWsControllerApi* | [**generateSumehrV210**](docs/KmehrWsControllerApi.md#generatesumehrv210) | **PUT** /ws/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV211**](docs/KmehrWsControllerApi.md#generatesumehrv211) | **HEAD** /ws/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV212**](docs/KmehrWsControllerApi.md#generatesumehrv212) | **GET** /ws/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV213**](docs/KmehrWsControllerApi.md#generatesumehrv213) | **PATCH** /ws/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV214**](docs/KmehrWsControllerApi.md#generatesumehrv214) | **OPTIONS** /ws/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV215**](docs/KmehrWsControllerApi.md#generatesumehrv215) | **DELETE** /ws/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV22**](docs/KmehrWsControllerApi.md#generatesumehrv22) | **POST** /ws/v2/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV23**](docs/KmehrWsControllerApi.md#generatesumehrv23) | **PUT** /ws/v2/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV24**](docs/KmehrWsControllerApi.md#generatesumehrv24) | **HEAD** /ws/v2/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV25**](docs/KmehrWsControllerApi.md#generatesumehrv25) | **GET** /ws/v2/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV26**](docs/KmehrWsControllerApi.md#generatesumehrv26) | **PATCH** /ws/v2/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV27**](docs/KmehrWsControllerApi.md#generatesumehrv27) | **OPTIONS** /ws/v2/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV28**](docs/KmehrWsControllerApi.md#generatesumehrv28) | **DELETE** /ws/v2/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV29**](docs/KmehrWsControllerApi.md#generatesumehrv29) | **POST** /ws/be_kmehr/generateSumehrV2 | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON**](docs/KmehrWsControllerApi.md#generatesumehrv2json) | **POST** /ws/v2/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON1**](docs/KmehrWsControllerApi.md#generatesumehrv2json1) | **PUT** /ws/v2/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON10**](docs/KmehrWsControllerApi.md#generatesumehrv2json10) | **GET** /ws/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON11**](docs/KmehrWsControllerApi.md#generatesumehrv2json11) | **PATCH** /ws/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON12**](docs/KmehrWsControllerApi.md#generatesumehrv2json12) | **OPTIONS** /ws/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON13**](docs/KmehrWsControllerApi.md#generatesumehrv2json13) | **DELETE** /ws/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON2**](docs/KmehrWsControllerApi.md#generatesumehrv2json2) | **HEAD** /ws/v2/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON3**](docs/KmehrWsControllerApi.md#generatesumehrv2json3) | **GET** /ws/v2/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON4**](docs/KmehrWsControllerApi.md#generatesumehrv2json4) | **PATCH** /ws/v2/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON5**](docs/KmehrWsControllerApi.md#generatesumehrv2json5) | **OPTIONS** /ws/v2/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON6**](docs/KmehrWsControllerApi.md#generatesumehrv2json6) | **DELETE** /ws/v2/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON7**](docs/KmehrWsControllerApi.md#generatesumehrv2json7) | **POST** /ws/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON8**](docs/KmehrWsControllerApi.md#generatesumehrv2json8) | **PUT** /ws/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**generateSumehrV2JSON9**](docs/KmehrWsControllerApi.md#generatesumehrv2json9) | **HEAD** /ws/be_kmehr/generateSumehrV2JSON | 
*KmehrWsControllerApi* | [**validateSumehr10**](docs/KmehrWsControllerApi.md#validatesumehr10) | **PUT** /ws/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr11**](docs/KmehrWsControllerApi.md#validatesumehr11) | **HEAD** /ws/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr12**](docs/KmehrWsControllerApi.md#validatesumehr12) | **GET** /ws/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr13**](docs/KmehrWsControllerApi.md#validatesumehr13) | **PATCH** /ws/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr14**](docs/KmehrWsControllerApi.md#validatesumehr14) | **OPTIONS** /ws/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr15**](docs/KmehrWsControllerApi.md#validatesumehr15) | **DELETE** /ws/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr2**](docs/KmehrWsControllerApi.md#validatesumehr2) | **POST** /ws/v2/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr3**](docs/KmehrWsControllerApi.md#validatesumehr3) | **PUT** /ws/v2/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr4**](docs/KmehrWsControllerApi.md#validatesumehr4) | **HEAD** /ws/v2/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr5**](docs/KmehrWsControllerApi.md#validatesumehr5) | **GET** /ws/v2/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr6**](docs/KmehrWsControllerApi.md#validatesumehr6) | **PATCH** /ws/v2/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr7**](docs/KmehrWsControllerApi.md#validatesumehr7) | **OPTIONS** /ws/v2/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr8**](docs/KmehrWsControllerApi.md#validatesumehr8) | **DELETE** /ws/v2/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehr9**](docs/KmehrWsControllerApi.md#validatesumehr9) | **POST** /ws/be_kmehr/validateSumehr | 
*KmehrWsControllerApi* | [**validateSumehrV210**](docs/KmehrWsControllerApi.md#validatesumehrv210) | **PUT** /ws/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV211**](docs/KmehrWsControllerApi.md#validatesumehrv211) | **HEAD** /ws/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV212**](docs/KmehrWsControllerApi.md#validatesumehrv212) | **GET** /ws/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV213**](docs/KmehrWsControllerApi.md#validatesumehrv213) | **PATCH** /ws/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV214**](docs/KmehrWsControllerApi.md#validatesumehrv214) | **OPTIONS** /ws/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV215**](docs/KmehrWsControllerApi.md#validatesumehrv215) | **DELETE** /ws/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV22**](docs/KmehrWsControllerApi.md#validatesumehrv22) | **POST** /ws/v2/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV23**](docs/KmehrWsControllerApi.md#validatesumehrv23) | **PUT** /ws/v2/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV24**](docs/KmehrWsControllerApi.md#validatesumehrv24) | **HEAD** /ws/v2/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV25**](docs/KmehrWsControllerApi.md#validatesumehrv25) | **GET** /ws/v2/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV26**](docs/KmehrWsControllerApi.md#validatesumehrv26) | **PATCH** /ws/v2/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV27**](docs/KmehrWsControllerApi.md#validatesumehrv27) | **OPTIONS** /ws/v2/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV28**](docs/KmehrWsControllerApi.md#validatesumehrv28) | **DELETE** /ws/v2/be_kmehr/validateSumehrV2 | 
*KmehrWsControllerApi* | [**validateSumehrV29**](docs/KmehrWsControllerApi.md#validatesumehrv29) | **POST** /ws/be_kmehr/validateSumehrV2 | 
*MedexApi* | [**generateMedex**](docs/MedexApi.md#generatemedex) | **POST** /rest/v2/medex/generate | Generate a Medex XML String
*MedexApi* | [**generateMedex1**](docs/MedexApi.md#generatemedex1) | **POST** /rest/v1/medex/generate | Generate a Medex XML String
*MedicallocationApi* | [**createMedicalLocation**](docs/MedicallocationApi.md#createmedicallocation) | **POST** /rest/v2/medicallocation | Creates a medical location
*MedicallocationApi* | [**createMedicalLocation1**](docs/MedicallocationApi.md#createmedicallocation1) | **POST** /rest/v1/medicallocation | Creates a medical location
*MedicallocationApi* | [**deleteMedicalLocation**](docs/MedicallocationApi.md#deletemedicallocation) | **DELETE** /rest/v1/medicallocation/{locationIds} | Deletes a medical location
*MedicallocationApi* | [**deleteMedicalLocations**](docs/MedicallocationApi.md#deletemedicallocations) | **DELETE** /rest/v2/medicallocation/delete/batch | Deletes medical locations
*MedicallocationApi* | [**getMedicalLocation**](docs/MedicallocationApi.md#getmedicallocation) | **GET** /rest/v2/medicallocation/{locationId} | Gets a medical location
*MedicallocationApi* | [**getMedicalLocation1**](docs/MedicallocationApi.md#getmedicallocation1) | **GET** /rest/v1/medicallocation/{locationId} | Gets a medical location
*MedicallocationApi* | [**getMedicalLocations**](docs/MedicallocationApi.md#getmedicallocations) | **GET** /rest/v2/medicallocation | Gets all medical locations
*MedicallocationApi* | [**getMedicalLocations1**](docs/MedicallocationApi.md#getmedicallocations1) | **GET** /rest/v1/medicallocation | Gets all medical locations
*MedicallocationApi* | [**modifyMedicalLocation**](docs/MedicallocationApi.md#modifymedicallocation) | **PUT** /rest/v2/medicallocation | Modifies a medical location
*MedicallocationApi* | [**modifyMedicalLocation1**](docs/MedicallocationApi.md#modifymedicallocation1) | **PUT** /rest/v1/medicallocation | Modifies a medical location
*MessageApi* | [**createMessage**](docs/MessageApi.md#createmessage) | **POST** /rest/v2/message | Creates a message
*MessageApi* | [**createMessage1**](docs/MessageApi.md#createmessage1) | **POST** /rest/v1/message | Creates a message
*MessageApi* | [**deleteDelegation**](docs/MessageApi.md#deletedelegation) | **DELETE** /rest/v2/message/{messageId}/delegate/{delegateId} | Deletes a message delegation
*MessageApi* | [**deleteDelegation1**](docs/MessageApi.md#deletedelegation1) | **DELETE** /rest/v1/message/{messageId}/delegate/{delegateId} | Deletes a message delegation
*MessageApi* | [**deleteMessages**](docs/MessageApi.md#deletemessages) | **POST** /rest/v2/message/delete/batch | Deletes multiple messages
*MessageApi* | [**deleteMessages1**](docs/MessageApi.md#deletemessages1) | **DELETE** /rest/v1/message/{messageIds} | Deletes multiple messages
*MessageApi* | [**deleteMessagesBatch**](docs/MessageApi.md#deletemessagesbatch) | **POST** /rest/v1/message/delete/byIds | Deletes multiple messages
*MessageApi* | [**findMessages**](docs/MessageApi.md#findmessages) | **GET** /rest/v2/message | Get all messages (paginated) for current HC Party
*MessageApi* | [**findMessages1**](docs/MessageApi.md#findmessages1) | **GET** /rest/v1/message | Get all messages (paginated) for current HC Party
*MessageApi* | [**findMessagesByFromAddress**](docs/MessageApi.md#findmessagesbyfromaddress) | **GET** /rest/v2/message/byFromAddress | Get all messages (paginated) for current HC Party and provided from address
*MessageApi* | [**findMessagesByFromAddress1**](docs/MessageApi.md#findmessagesbyfromaddress1) | **GET** /rest/v1/message/byFromAddress | Get all messages (paginated) for current HC Party and provided from address
*MessageApi* | [**findMessagesByHCPartyPatientForeignKeys**](docs/MessageApi.md#findmessagesbyhcpartypatientforeignkeys) | **GET** /rest/v2/message/byHcPartySecretForeignKeys | List messages found By Healthcare Party and secret foreign keys.
*MessageApi* | [**findMessagesByHCPartyPatientForeignKeys1**](docs/MessageApi.md#findmessagesbyhcpartypatientforeignkeys1) | **GET** /rest/v1/message/byHcPartySecretForeignKeys | List messages found By Healthcare Party and secret foreign keys.
*MessageApi* | [**findMessagesByToAddress**](docs/MessageApi.md#findmessagesbytoaddress) | **GET** /rest/v2/message/byToAddress | Get all messages (paginated) for current HC Party and provided to address
*MessageApi* | [**findMessagesByToAddress1**](docs/MessageApi.md#findmessagesbytoaddress1) | **GET** /rest/v1/message/byToAddress | Get all messages (paginated) for current HC Party and provided to address
*MessageApi* | [**findMessagesByTransportGuid**](docs/MessageApi.md#findmessagesbytransportguid) | **GET** /rest/v2/message/byTransportGuid | Get all messages (paginated) for current HC Party and provided transportGuid
*MessageApi* | [**findMessagesByTransportGuid1**](docs/MessageApi.md#findmessagesbytransportguid1) | **GET** /rest/v1/message/byTransportGuid | Get all messages (paginated) for current HC Party and provided transportGuid
*MessageApi* | [**findMessagesByTransportGuidSentDate**](docs/MessageApi.md#findmessagesbytransportguidsentdate) | **GET** /rest/v2/message/byTransportGuidSentDate | Get all messages starting by a prefix between two date
*MessageApi* | [**findMessagesByTransportGuidSentDate1**](docs/MessageApi.md#findmessagesbytransportguidsentdate1) | **GET** /rest/v1/message/byTransportGuidSentDate | Get all messages starting by a prefix between two date
*MessageApi* | [**getChildrenMessages**](docs/MessageApi.md#getchildrenmessages) | **GET** /rest/v2/message/{messageId}/children | Get children messages of provided message
*MessageApi* | [**getChildrenMessages1**](docs/MessageApi.md#getchildrenmessages1) | **GET** /rest/v1/message/{messageId}/children | Get children messages of provided message
*MessageApi* | [**getChildrenMessagesOfList**](docs/MessageApi.md#getchildrenmessagesoflist) | **POST** /rest/v1/message/children/batch | Get children messages of provided message
*MessageApi* | [**getMessage**](docs/MessageApi.md#getmessage) | **GET** /rest/v2/message/{messageId} | Gets a message
*MessageApi* | [**getMessage1**](docs/MessageApi.md#getmessage1) | **GET** /rest/v1/message/{messageId} | Gets a message
*MessageApi* | [**getMessagesChildren**](docs/MessageApi.md#getmessageschildren) | **POST** /rest/v2/message/children/batch | Get children messages of provided message
*MessageApi* | [**listMessagesByInvoiceIds**](docs/MessageApi.md#listmessagesbyinvoiceids) | **POST** /rest/v1/message/byInvoiceId | Get children messages of provided message
*MessageApi* | [**listMessagesByInvoices**](docs/MessageApi.md#listmessagesbyinvoices) | **POST** /rest/v2/message/byInvoice | Get children messages of provided message
*MessageApi* | [**listMessagesByTransportGuids**](docs/MessageApi.md#listmessagesbytransportguids) | **POST** /rest/v2/message/byTransportGuid/list | Get all messages for current HC Party and provided transportGuids
*MessageApi* | [**listMessagesByTransportGuids1**](docs/MessageApi.md#listmessagesbytransportguids1) | **POST** /rest/v1/message/byTransportGuid/list | Get all messages for current HC Party and provided transportGuids
*MessageApi* | [**modifyMessage**](docs/MessageApi.md#modifymessage) | **PUT** /rest/v2/message | Updates a message
*MessageApi* | [**modifyMessage1**](docs/MessageApi.md#modifymessage1) | **PUT** /rest/v1/message | Updates a message
*MessageApi* | [**newMessageDelegations**](docs/MessageApi.md#newmessagedelegations) | **PUT** /rest/v2/message/{messageId}/delegate | Adds a delegation to a message
*MessageApi* | [**newMessageDelegations1**](docs/MessageApi.md#newmessagedelegations1) | **PUT** /rest/v1/message/{messageId}/delegate | Adds a delegation to a message
*MessageApi* | [**setMessagesReadStatus**](docs/MessageApi.md#setmessagesreadstatus) | **PUT** /rest/v2/message/readstatus | Set read status for given list of messages
*MessageApi* | [**setMessagesReadStatus1**](docs/MessageApi.md#setmessagesreadstatus1) | **PUT** /rest/v1/message/readstatus | Set read status for given list of messages
*MessageApi* | [**setMessagesStatusBits**](docs/MessageApi.md#setmessagesstatusbits) | **PUT** /rest/v2/message/status/{status} | Set status bits for given list of messages
*MessageApi* | [**setMessagesStatusBits1**](docs/MessageApi.md#setmessagesstatusbits1) | **PUT** /rest/v1/message/status/{status} | Set status bits for given list of messages
*PatientApi* | [**bulkCreatePatients**](docs/PatientApi.md#bulkcreatepatients) | **POST** /rest/v1/patient/batch | Create patients in bulk
*PatientApi* | [**bulkCreatePatients1**](docs/PatientApi.md#bulkcreatepatients1) | **POST** /rest/v1/patient/bulk | Create patients in bulk
*PatientApi* | [**bulkUpdatePatients**](docs/PatientApi.md#bulkupdatepatients) | **PUT** /rest/v1/patient/batch | Modify patients in bulk
*PatientApi* | [**bulkUpdatePatients1**](docs/PatientApi.md#bulkupdatepatients1) | **PUT** /rest/v1/patient/bulk | Modify patients in bulk
*PatientApi* | [**countOfPatients**](docs/PatientApi.md#countofpatients) | **GET** /rest/v2/patient/hcParty/{hcPartyId}/count | Get count of patients for a specific HcParty or for the current HcParty 
*PatientApi* | [**countOfPatients1**](docs/PatientApi.md#countofpatients1) | **GET** /rest/v1/patient/hcParty/{hcPartyId}/count | Get count of patients for a specific HcParty or for the current HcParty 
*PatientApi* | [**createPatient**](docs/PatientApi.md#createpatient) | **POST** /rest/v2/patient | Create a patient
*PatientApi* | [**createPatient1**](docs/PatientApi.md#createpatient1) | **POST** /rest/v1/patient | Create a patient
*PatientApi* | [**createPatients**](docs/PatientApi.md#createpatients) | **POST** /rest/v2/patient/batch | Create patients in bulk
*PatientApi* | [**deletePatient**](docs/PatientApi.md#deletepatient) | **DELETE** /rest/v1/patient/{patientIds} | Delete patients.
*PatientApi* | [**deletePatients**](docs/PatientApi.md#deletepatients) | **POST** /rest/v2/patient/delete/batch | Delete patients.
*PatientApi* | [**filterPatientsBy**](docs/PatientApi.md#filterpatientsby) | **POST** /rest/v2/patient/filter | Filter patients for the current user (HcParty) 
*PatientApi* | [**filterPatientsBy1**](docs/PatientApi.md#filterpatientsby1) | **POST** /rest/v1/patient/filter | Filter patients for the current user (HcParty) 
*PatientApi* | [**findByAccessLogUserAfterDate**](docs/PatientApi.md#findbyaccessloguserafterdate) | **GET** /rest/v1/patient/byAccess/{userId} | Get Paginated List of Patients sorted by Access logs descending
*PatientApi* | [**findByExternalId**](docs/PatientApi.md#findbyexternalid) | **GET** /rest/v2/patient/byExternalId/{externalId} | Get the patient having the provided externalId
*PatientApi* | [**findByExternalId1**](docs/PatientApi.md#findbyexternalid1) | **GET** /rest/v1/patient/byExternalId/{externalId} | Get the patient having the provided externalId
*PatientApi* | [**findByNameBirthSsinAuto**](docs/PatientApi.md#findbynamebirthssinauto) | **GET** /rest/v1/patient/byNameBirthSsinAuto | Find patients for the current user (HcParty) 
*PatientApi* | [**findDeletedPatients**](docs/PatientApi.md#finddeletedpatients) | **GET** /rest/v2/patient/deleted/byDate | Find deleted patients
*PatientApi* | [**findPatientsByAccessLogUserAfterDate**](docs/PatientApi.md#findpatientsbyaccessloguserafterdate) | **GET** /rest/v2/patient/byAccess/{userId} | Get Paginated List of Patients sorted by Access logs descending
*PatientApi* | [**findPatientsByHealthcareParty**](docs/PatientApi.md#findpatientsbyhealthcareparty) | **GET** /rest/v2/patient | List patients for a specific HcParty
*PatientApi* | [**findPatientsByNameBirthSsinAuto**](docs/PatientApi.md#findpatientsbynamebirthssinauto) | **GET** /rest/v2/patient/byNameBirthSsinAuto | Find patients for the current user (HcParty) 
*PatientApi* | [**findPatientsIdsByHealthcareParty**](docs/PatientApi.md#findpatientsidsbyhealthcareparty) | **GET** /rest/v2/patient/byHcPartyId | List patients by pages for a specific HcParty
*PatientApi* | [**findPatientsModifiedAfter**](docs/PatientApi.md#findpatientsmodifiedafter) | **GET** /rest/v2/patient/modifiedAfter/{date} | List patients that have been modified after the provided date
*PatientApi* | [**fuzzySearch**](docs/PatientApi.md#fuzzysearch) | **GET** /rest/v2/patient/fuzzy | Filter patients for the current user (HcParty) 
*PatientApi* | [**fuzzySearch1**](docs/PatientApi.md#fuzzysearch1) | **GET** /rest/v1/patient/fuzzy | Filter patients for the current user (HcParty) 
*PatientApi* | [**getPatient**](docs/PatientApi.md#getpatient) | **GET** /rest/v2/patient/{patientId} | Get patient
*PatientApi* | [**getPatient1**](docs/PatientApi.md#getpatient1) | **GET** /rest/v1/patient/{patientId} | Get patient
*PatientApi* | [**getPatientByHealrhcarepartyAndIdentifier**](docs/PatientApi.md#getpatientbyhealrhcarepartyandidentifier) | **GET** /rest/v1/patient/{hcPartyId}/{system}/{id} | Get patient by identifier
*PatientApi* | [**getPatientHcPartyKeysForDelegate**](docs/PatientApi.md#getpatienthcpartykeysfordelegate) | **GET** /rest/v2/patient/{patientId}/keys | Get the patient (identified by patientId) hcparty keys. Those keys are AES keys (encrypted) used to share information between HCPs and a patient.
*PatientApi* | [**getPatientHcPartyKeysForDelegate1**](docs/PatientApi.md#getpatienthcpartykeysfordelegate1) | **GET** /rest/v1/patient/{patientId}/keys | Get the patient (identified by patientId) hcparty keys. Those keys are AES keys (encrypted) used to share information between HCPs and a patient.
*PatientApi* | [**getPatients**](docs/PatientApi.md#getpatients) | **POST** /rest/v2/patient/byIds | Get patients by id
*PatientApi* | [**getPatients1**](docs/PatientApi.md#getpatients1) | **POST** /rest/v1/patient/byIds | Get patients by id
*PatientApi* | [**listDeletedPatients**](docs/PatientApi.md#listdeletedpatients) | **GET** /rest/v1/patient/deleted/by_date | Find deleted patients
*PatientApi* | [**listDeletedPatientsByName**](docs/PatientApi.md#listdeletedpatientsbyname) | **GET** /rest/v2/patient/deleted/by_name | Find deleted patients
*PatientApi* | [**listDeletedPatientsByName1**](docs/PatientApi.md#listdeletedpatientsbyname1) | **GET** /rest/v1/patient/deleted/by_name | Find deleted patients
*PatientApi* | [**listOfMergesAfter**](docs/PatientApi.md#listofmergesafter) | **GET** /rest/v2/patient/merges/{date} | List patients that have been merged towards another patient 
*PatientApi* | [**listOfMergesAfter1**](docs/PatientApi.md#listofmergesafter1) | **GET** /rest/v1/patient/merges/{date} | List patients that have been merged towards another patient 
*PatientApi* | [**listOfPatientsModifiedAfter**](docs/PatientApi.md#listofpatientsmodifiedafter) | **GET** /rest/v1/patient/modifiedAfter/{date} | List patients that have been modified after the provided date
*PatientApi* | [**listPatients**](docs/PatientApi.md#listpatients) | **GET** /rest/v1/patient | List patients for a specific HcParty
*PatientApi* | [**listPatientsByHcParty**](docs/PatientApi.md#listpatientsbyhcparty) | **GET** /rest/v1/patient/hcParty/{hcPartyId} | List patients for a specific HcParty or for the current HcParty 
*PatientApi* | [**listPatientsIds**](docs/PatientApi.md#listpatientsids) | **GET** /rest/v1/patient/idsPages | List patients by pages for a specific HcParty
*PatientApi* | [**listPatientsOfHcParty**](docs/PatientApi.md#listpatientsofhcparty) | **GET** /rest/v1/patient/ofHcParty/{hcPartyId} | List patients of a specific HcParty or of the current HcParty 
*PatientApi* | [**matchPatientsBy**](docs/PatientApi.md#matchpatientsby) | **POST** /rest/v2/patient/match | Get ids of patients matching the provided filter for the current user (HcParty) 
*PatientApi* | [**matchPatientsBy1**](docs/PatientApi.md#matchpatientsby1) | **POST** /rest/v1/patient/match | Get ids of patients matching the provided filter for the current user (HcParty) 
*PatientApi* | [**mergeInto**](docs/PatientApi.md#mergeinto) | **PUT** /rest/v2/patient/mergeInto/{toId}/from/{fromIds} | Merge a series of patients into another patient
*PatientApi* | [**mergeInto1**](docs/PatientApi.md#mergeinto1) | **PUT** /rest/v1/patient/mergeInto/{toId}/from/{fromIds} | Merge a series of patients into another patient
*PatientApi* | [**modifyPatient**](docs/PatientApi.md#modifypatient) | **PUT** /rest/v2/patient | Modify a patient
*PatientApi* | [**modifyPatient1**](docs/PatientApi.md#modifypatient1) | **PUT** /rest/v1/patient | Modify a patient
*PatientApi* | [**modifyPatientReferral**](docs/PatientApi.md#modifypatientreferral) | **PUT** /rest/v2/patient/{patientId}/referral/{referralId} | Set a patient referral doctor
*PatientApi* | [**modifyPatientReferral1**](docs/PatientApi.md#modifypatientreferral1) | **PUT** /rest/v1/patient/{patientId}/referral/{referralId} | Set a patient referral doctor
*PatientApi* | [**modifyPatients**](docs/PatientApi.md#modifypatients) | **PUT** /rest/v2/patient/batch | Modify patients in bulk
*PatientApi* | [**newPatientDelegations**](docs/PatientApi.md#newpatientdelegations) | **POST** /rest/v2/patient/{patientId}/delegate | Delegates a patients to a healthcare party
*PatientApi* | [**newPatientDelegations1**](docs/PatientApi.md#newpatientdelegations1) | **POST** /rest/v1/patient/{patientId}/delegate | Delegates a patients to a healthcare party
*PatientApi* | [**undeletePatient**](docs/PatientApi.md#undeletepatient) | **PUT** /rest/v2/patient/undelete/{patientIds} | undelete previously deleted patients
*PatientApi* | [**undeletePatient1**](docs/PatientApi.md#undeletepatient1) | **PUT** /rest/v1/patient/undelete/{patientIds} | undelete previously deleted patients
*PlaceApi* | [**createPlace**](docs/PlaceApi.md#createplace) | **POST** /rest/v2/place | Creates a place
*PlaceApi* | [**createPlace1**](docs/PlaceApi.md#createplace1) | **POST** /rest/v1/place | Creates a place
*PlaceApi* | [**deletePlace**](docs/PlaceApi.md#deleteplace) | **DELETE** /rest/v1/place/{placeIds} | Deletes an place
*PlaceApi* | [**deletePlaces**](docs/PlaceApi.md#deleteplaces) | **POST** /rest/v2/place/delete/batch | Deletes places
*PlaceApi* | [**getPlace**](docs/PlaceApi.md#getplace) | **GET** /rest/v2/place/{placeId} | Gets an place
*PlaceApi* | [**getPlace1**](docs/PlaceApi.md#getplace1) | **GET** /rest/v1/place/{placeId} | Gets an place
*PlaceApi* | [**getPlaces**](docs/PlaceApi.md#getplaces) | **GET** /rest/v2/place | Gets all places
*PlaceApi* | [**getPlaces1**](docs/PlaceApi.md#getplaces1) | **GET** /rest/v1/place | Gets all places
*PlaceApi* | [**modifyPlace**](docs/PlaceApi.md#modifyplace) | **PUT** /rest/v2/place | Modifies an place
*PlaceApi* | [**modifyPlace1**](docs/PlaceApi.md#modifyplace1) | **PUT** /rest/v1/place | Modifies an place
*PubSubControllerApi* | [**pub1**](docs/PubSubControllerApi.md#pub1) | **POST** /ws/v2/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub10**](docs/PubSubControllerApi.md#pub10) | **HEAD** /ws/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub11**](docs/PubSubControllerApi.md#pub11) | **GET** /ws/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub12**](docs/PubSubControllerApi.md#pub12) | **PATCH** /ws/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub13**](docs/PubSubControllerApi.md#pub13) | **OPTIONS** /ws/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub14**](docs/PubSubControllerApi.md#pub14) | **DELETE** /ws/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub2**](docs/PubSubControllerApi.md#pub2) | **PUT** /ws/v2/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub3**](docs/PubSubControllerApi.md#pub3) | **HEAD** /ws/v2/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub4**](docs/PubSubControllerApi.md#pub4) | **GET** /ws/v2/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub5**](docs/PubSubControllerApi.md#pub5) | **PATCH** /ws/v2/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub6**](docs/PubSubControllerApi.md#pub6) | **OPTIONS** /ws/v2/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub7**](docs/PubSubControllerApi.md#pub7) | **DELETE** /ws/v2/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub8**](docs/PubSubControllerApi.md#pub8) | **POST** /ws/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**pub9**](docs/PubSubControllerApi.md#pub9) | **PUT** /ws/pubsub/{topic}/pub | 
*PubSubControllerApi* | [**sub1**](docs/PubSubControllerApi.md#sub1) | **POST** /ws/v2/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub10**](docs/PubSubControllerApi.md#sub10) | **HEAD** /ws/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub11**](docs/PubSubControllerApi.md#sub11) | **GET** /ws/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub12**](docs/PubSubControllerApi.md#sub12) | **PATCH** /ws/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub13**](docs/PubSubControllerApi.md#sub13) | **OPTIONS** /ws/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub14**](docs/PubSubControllerApi.md#sub14) | **DELETE** /ws/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub2**](docs/PubSubControllerApi.md#sub2) | **PUT** /ws/v2/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub3**](docs/PubSubControllerApi.md#sub3) | **HEAD** /ws/v2/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub4**](docs/PubSubControllerApi.md#sub4) | **GET** /ws/v2/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub5**](docs/PubSubControllerApi.md#sub5) | **PATCH** /ws/v2/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub6**](docs/PubSubControllerApi.md#sub6) | **OPTIONS** /ws/v2/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub7**](docs/PubSubControllerApi.md#sub7) | **DELETE** /ws/v2/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub8**](docs/PubSubControllerApi.md#sub8) | **POST** /ws/pubsub/{topic}/sub | 
*PubSubControllerApi* | [**sub9**](docs/PubSubControllerApi.md#sub9) | **PUT** /ws/pubsub/{topic}/sub | 
*PubsubApi* | [**offerAuth**](docs/PubsubApi.md#offerauth) | **PUT** /rest/v1/pubsub/auth/{bucket} | Offer auth data on secret bucket
*PubsubApi* | [**pub**](docs/PubsubApi.md#pub) | **PUT** /rest/v1/pubsub/pub/{key} | publish data
*PubsubApi* | [**recoverAuth**](docs/PubsubApi.md#recoverauth) | **GET** /rest/v1/pubsub/auth/recover/{bucket} | Recover auth data from secret bucket
*PubsubApi* | [**sub**](docs/PubsubApi.md#sub) | **GET** /rest/v1/pubsub/sub/{key} | subscribe to data
*ReceiptApi* | [**createReceipt**](docs/ReceiptApi.md#createreceipt) | **POST** /rest/v2/receipt | Creates a receipt
*ReceiptApi* | [**createReceipt1**](docs/ReceiptApi.md#createreceipt1) | **POST** /rest/v1/receipt | Creates a receipt
*ReceiptApi* | [**deleteReceipt**](docs/ReceiptApi.md#deletereceipt) | **DELETE** /rest/v1/receipt/{receiptIds} | Deletes a receipt
*ReceiptApi* | [**deleteReceipts**](docs/ReceiptApi.md#deletereceipts) | **DELETE** /rest/v2/receipt/delete/batch | Deletes receipts
*ReceiptApi* | [**getReceipt**](docs/ReceiptApi.md#getreceipt) | **GET** /rest/v2/receipt/{receiptId} | Gets a receipt
*ReceiptApi* | [**getReceipt1**](docs/ReceiptApi.md#getreceipt1) | **GET** /rest/v1/receipt/{receiptId} | Gets a receipt
*ReceiptApi* | [**getReceiptAttachment**](docs/ReceiptApi.md#getreceiptattachment) | **GET** /rest/v2/receipt/{receiptId}/attachment/{attachmentId} | Get an attachment
*ReceiptApi* | [**getReceiptAttachment1**](docs/ReceiptApi.md#getreceiptattachment1) | **GET** /rest/v1/receipt/{receiptId}/attachment/{attachmentId} | Get an attachment
*ReceiptApi* | [**listByReference**](docs/ReceiptApi.md#listbyreference) | **GET** /rest/v2/receipt/byRef/{ref} | Gets a receipt
*ReceiptApi* | [**listByReference1**](docs/ReceiptApi.md#listbyreference1) | **GET** /rest/v1/receipt/byref/{ref} | Gets a receipt
*ReceiptApi* | [**modifyReceipt**](docs/ReceiptApi.md#modifyreceipt) | **PUT** /rest/v2/receipt | Updates a receipt
*ReceiptApi* | [**modifyReceipt1**](docs/ReceiptApi.md#modifyreceipt1) | **PUT** /rest/v1/receipt | Updates a receipt
*ReceiptApi* | [**setReceiptAttachment**](docs/ReceiptApi.md#setreceiptattachment) | **PUT** /rest/v2/receipt/{receiptId}/attachment/{blobType} | Creates a receipt's attachment
*ReceiptApi* | [**setReceiptAttachment1**](docs/ReceiptApi.md#setreceiptattachment1) | **PUT** /rest/v1/receipt/{receiptId}/attachment/{blobType} | Creates a receipt's attachment
*TarificationApi* | [**createTarification**](docs/TarificationApi.md#createtarification) | **POST** /rest/v2/tarification | Create a Tarification
*TarificationApi* | [**createTarification1**](docs/TarificationApi.md#createtarification1) | **POST** /rest/v1/tarification | Create a Tarification
*TarificationApi* | [**findPaginatedTarifications**](docs/TarificationApi.md#findpaginatedtarifications) | **GET** /rest/v1/tarification | Finding tarifications by tarification, type and version with pagination.
*TarificationApi* | [**findPaginatedTarificationsByLabel**](docs/TarificationApi.md#findpaginatedtarificationsbylabel) | **GET** /rest/v1/tarification/byLabel | Finding tarifications by tarification, type and version with pagination.
*TarificationApi* | [**findTarifications**](docs/TarificationApi.md#findtarifications) | **GET** /rest/v1/tarification/byRegionTypeTarification | Finding tarifications by tarification, type and version
*TarificationApi* | [**findTarificationsBy**](docs/TarificationApi.md#findtarificationsby) | **GET** /rest/v2/tarification | Finding tarifications by tarification, type and version with pagination.
*TarificationApi* | [**findTarificationsBy1**](docs/TarificationApi.md#findtarificationsby1) | **GET** /rest/v2/tarification/byRegionTypeTarification | Finding tarifications by tarification, type and version
*TarificationApi* | [**findTarificationsByLabel**](docs/TarificationApi.md#findtarificationsbylabel) | **GET** /rest/v2/tarification/byLabel | Finding tarifications by tarification, type and version with pagination.
*TarificationApi* | [**getTarification**](docs/TarificationApi.md#gettarification) | **GET** /rest/v2/tarification/{tarificationId} | Get a tarification
*TarificationApi* | [**getTarification1**](docs/TarificationApi.md#gettarification1) | **GET** /rest/v1/tarification/{tarificationId} | Get a tarification
*TarificationApi* | [**getTarificationWithParts**](docs/TarificationApi.md#gettarificationwithparts) | **GET** /rest/v2/tarification/{type}/{tarification}/{version} | Get a tarification
*TarificationApi* | [**getTarificationWithParts1**](docs/TarificationApi.md#gettarificationwithparts1) | **GET** /rest/v1/tarification/{type}/{tarification}/{version} | Get a tarification
*TarificationApi* | [**getTarifications**](docs/TarificationApi.md#gettarifications) | **POST** /rest/v2/tarification/byIds | Get a list of tarifications by ids
*TarificationApi* | [**getTarifications1**](docs/TarificationApi.md#gettarifications1) | **POST** /rest/v1/tarification/byIds | Get a list of tarifications by ids
*TarificationApi* | [**modifyTarification**](docs/TarificationApi.md#modifytarification) | **PUT** /rest/v2/tarification | Modify a tarification
*TarificationApi* | [**modifyTarification1**](docs/TarificationApi.md#modifytarification1) | **PUT** /rest/v1/tarification | Modify a tarification
*TimeTableApi* | [**createTimeTable**](docs/TimeTableApi.md#createtimetable) | **POST** /rest/v2/timeTable | Creates a timeTable
*TimeTableApi* | [**createTimeTable1**](docs/TimeTableApi.md#createtimetable1) | **POST** /rest/v1/timeTable | Creates a timeTable
*TimeTableApi* | [**deleteTimeTable**](docs/TimeTableApi.md#deletetimetable) | **POST** /rest/v2/timeTable/delete/batch | Deletes an timeTable
*TimeTableApi* | [**deleteTimeTable1**](docs/TimeTableApi.md#deletetimetable1) | **DELETE** /rest/v1/timeTable/{timeTableIds} | Deletes an timeTable
*TimeTableApi* | [**getTimeTable**](docs/TimeTableApi.md#gettimetable) | **GET** /rest/v2/timeTable/{timeTableId} | Gets a timeTable
*TimeTableApi* | [**getTimeTable1**](docs/TimeTableApi.md#gettimetable1) | **GET** /rest/v1/timeTable/{timeTableId} | Gets a timeTable
*TimeTableApi* | [**getTimeTablesByAgendaId**](docs/TimeTableApi.md#gettimetablesbyagendaid) | **POST** /rest/v2/timeTable/byAgendaId | Get TimeTables by AgendaId
*TimeTableApi* | [**getTimeTablesByAgendaId1**](docs/TimeTableApi.md#gettimetablesbyagendaid1) | **POST** /rest/v1/timeTable/byAgendaId | Get TimeTables by AgendaId
*TimeTableApi* | [**getTimeTablesByPeriodAndAgendaId**](docs/TimeTableApi.md#gettimetablesbyperiodandagendaid) | **POST** /rest/v2/timeTable/byPeriodAndAgendaId | Get TimeTables by Period and AgendaId
*TimeTableApi* | [**getTimeTablesByPeriodAndAgendaId1**](docs/TimeTableApi.md#gettimetablesbyperiodandagendaid1) | **POST** /rest/v1/timeTable/byPeriodAndAgendaId | Get TimeTables by Period and AgendaId
*TimeTableApi* | [**modifyTimeTable**](docs/TimeTableApi.md#modifytimetable) | **PUT** /rest/v2/timeTable | Modifies an timeTable
*TimeTableApi* | [**modifyTimeTable1**](docs/TimeTableApi.md#modifytimetable1) | **PUT** /rest/v1/timeTable | Modifies an timeTable
*TmpApi* | [**createTmpClassification**](docs/TmpApi.md#createtmpclassification) | **POST** /rest/v1/tmp/classification | Create a classification with the current user
*TmpApi* | [**createTmpClassifications**](docs/TmpApi.md#createtmpclassifications) | **POST** /rest/v1/tmp/classification/batch | Create a classification with the current user
*TmpApi* | [**createTmpContact**](docs/TmpApi.md#createtmpcontact) | **POST** /rest/v1/tmp/contact | Create a contact with the current user
*TmpApi* | [**createTmpContacts**](docs/TmpApi.md#createtmpcontacts) | **POST** /rest/v1/tmp/contact/batch | Create a contact with the current user
*TmpApi* | [**createTmpDatabase**](docs/TmpApi.md#createtmpdatabase) | **POST** /rest/v1/tmp | Create tmp database for current user
*TmpApi* | [**createTmpDocument**](docs/TmpApi.md#createtmpdocument) | **POST** /rest/v1/tmp/document | Create a document with the current user
*TmpApi* | [**createTmpDocuments**](docs/TmpApi.md#createtmpdocuments) | **POST** /rest/v1/tmp/document/batch | Create a document with the current user
*TmpApi* | [**createTmpEntityTemplate**](docs/TmpApi.md#createtmpentitytemplate) | **POST** /rest/v1/tmp/entityTemplate | Create a entityTemplate with the current user
*TmpApi* | [**createTmpEntityTemplates**](docs/TmpApi.md#createtmpentitytemplates) | **POST** /rest/v1/tmp/entityTemplate/batch | Create a entityTemplate with the current user
*TmpApi* | [**createTmpForm**](docs/TmpApi.md#createtmpform) | **POST** /rest/v1/tmp/form | Create a form with the current user
*TmpApi* | [**createTmpForms**](docs/TmpApi.md#createtmpforms) | **POST** /rest/v1/tmp/form/batch | Create a form with the current user
*TmpApi* | [**createTmpHealthElement**](docs/TmpApi.md#createtmphealthelement) | **POST** /rest/v1/tmp/healthElement | Create a healthElement with the current user
*TmpApi* | [**createTmpHealthElements**](docs/TmpApi.md#createtmphealthelements) | **POST** /rest/v1/tmp/healthElement/batch | Create a healthElement with the current user
*TmpApi* | [**createTmpInvoice**](docs/TmpApi.md#createtmpinvoice) | **POST** /rest/v1/tmp/invoice | Create a invoice with the current user
*TmpApi* | [**createTmpInvoices**](docs/TmpApi.md#createtmpinvoices) | **POST** /rest/v1/tmp/invoice/batch | Create a invoice with the current user
*TmpApi* | [**createTmpMessage**](docs/TmpApi.md#createtmpmessage) | **POST** /rest/v1/tmp/message | Create a message with the current user
*TmpApi* | [**createTmpMessages**](docs/TmpApi.md#createtmpmessages) | **POST** /rest/v1/tmp/message/batch | Create a message with the current user
*TmpApi* | [**createTmpPatient**](docs/TmpApi.md#createtmppatient) | **POST** /rest/v1/tmp/patient | Create a patient with the current user
*TmpApi* | [**createTmpPatients**](docs/TmpApi.md#createtmppatients) | **POST** /rest/v1/tmp/patient/batch | Create a patient with the current user
*TmpApi* | [**deleteTmpItems**](docs/TmpApi.md#deletetmpitems) | **POST** /rest/v1/tmp/batch/delete | Soft delete items.
*TmpApi* | [**destroyTmpDatabase**](docs/TmpApi.md#destroytmpdatabase) | **DELETE** /rest/v1/tmp | Destroy tmp database for current user
*TmpApi* | [**getTmpClassification**](docs/TmpApi.md#gettmpclassification) | **GET** /rest/v1/tmp/classification/byId/{id} | Get a classification by id
*TmpApi* | [**getTmpClassifications**](docs/TmpApi.md#gettmpclassifications) | **POST** /rest/v1/tmp/classification/get | Get classifications by ids with the current user
*TmpApi* | [**getTmpContact**](docs/TmpApi.md#gettmpcontact) | **GET** /rest/v1/tmp/contact/byId/{id} | Get a contact by id
*TmpApi* | [**getTmpContacts**](docs/TmpApi.md#gettmpcontacts) | **POST** /rest/v1/tmp/contact/get | Get contacts by ids with the current user
*TmpApi* | [**getTmpDocument**](docs/TmpApi.md#gettmpdocument) | **GET** /rest/v1/tmp/document/byId/{id} | Get a document by id
*TmpApi* | [**getTmpDocuments**](docs/TmpApi.md#gettmpdocuments) | **POST** /rest/v1/tmp/document/get | Get documents by ids with the current user
*TmpApi* | [**getTmpEntityTemplate**](docs/TmpApi.md#gettmpentitytemplate) | **GET** /rest/v1/tmp/entityTemplate/byId/{id} | Get a entityTemplate by id
*TmpApi* | [**getTmpEntityTemplates**](docs/TmpApi.md#gettmpentitytemplates) | **POST** /rest/v1/tmp/entityTemplate/get | Get entityTemplates by ids with the current user
*TmpApi* | [**getTmpForm**](docs/TmpApi.md#gettmpform) | **GET** /rest/v1/tmp/form/byId/{id} | Get a form by id
*TmpApi* | [**getTmpForms**](docs/TmpApi.md#gettmpforms) | **POST** /rest/v1/tmp/form/get | Get forms by ids with the current user
*TmpApi* | [**getTmpHealthElement**](docs/TmpApi.md#gettmphealthelement) | **GET** /rest/v1/tmp/healthElement/byId/{id} | Get a healthElement by id
*TmpApi* | [**getTmpHealthElements**](docs/TmpApi.md#gettmphealthelements) | **POST** /rest/v1/tmp/healthElement/get | Get healthElements by ids with the current user
*TmpApi* | [**getTmpInvoice**](docs/TmpApi.md#gettmpinvoice) | **GET** /rest/v1/tmp/invoice/byId/{id} | Get a invoice by id
*TmpApi* | [**getTmpInvoices**](docs/TmpApi.md#gettmpinvoices) | **POST** /rest/v1/tmp/invoice/get | Get invoices by ids with the current user
*TmpApi* | [**getTmpMessage**](docs/TmpApi.md#gettmpmessage) | **GET** /rest/v1/tmp/message/byId/{id} | Get a message by id
*TmpApi* | [**getTmpMessages**](docs/TmpApi.md#gettmpmessages) | **POST** /rest/v1/tmp/message/get | Get messages by ids with the current user
*TmpApi* | [**getTmpPatient**](docs/TmpApi.md#gettmppatient) | **GET** /rest/v1/tmp/patient/byId/{id} | Get a patient by id
*TmpApi* | [**getTmpPatients**](docs/TmpApi.md#gettmppatients) | **POST** /rest/v1/tmp/patient/get | Get patients by ids with the current user
*TmpApi* | [**listTmpClassifications**](docs/TmpApi.md#listtmpclassifications) | **GET** /rest/v1/tmp/classification/list | List classifications with the current user
*TmpApi* | [**listTmpContacts**](docs/TmpApi.md#listtmpcontacts) | **GET** /rest/v1/tmp/contact/list | List contacts with the current user
*TmpApi* | [**listTmpDocuments**](docs/TmpApi.md#listtmpdocuments) | **GET** /rest/v1/tmp/document/list | List documents with the current user
*TmpApi* | [**listTmpEntityTemplates**](docs/TmpApi.md#listtmpentitytemplates) | **GET** /rest/v1/tmp/entityTemplate/list | List entityTemplates with the current user
*TmpApi* | [**listTmpForms**](docs/TmpApi.md#listtmpforms) | **GET** /rest/v1/tmp/form/list | List forms with the current user
*TmpApi* | [**listTmpHealthElements**](docs/TmpApi.md#listtmphealthelements) | **GET** /rest/v1/tmp/healthElement/list | List healthElements with the current user
*TmpApi* | [**listTmpInvoices**](docs/TmpApi.md#listtmpinvoices) | **GET** /rest/v1/tmp/invoice/list | List invoices with the current user
*TmpApi* | [**listTmpMessages**](docs/TmpApi.md#listtmpmessages) | **GET** /rest/v1/tmp/message/list | List messages with the current user
*TmpApi* | [**listTmpPatients**](docs/TmpApi.md#listtmppatients) | **GET** /rest/v1/tmp/patient/list | List patients with the current user
*TmpApi* | [**modifyTmpClassification**](docs/TmpApi.md#modifytmpclassification) | **PUT** /rest/v1/tmp/classification | Modify a classification
*TmpApi* | [**modifyTmpClassifications**](docs/TmpApi.md#modifytmpclassifications) | **PUT** /rest/v1/tmp/classification/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpContact**](docs/TmpApi.md#modifytmpcontact) | **PUT** /rest/v1/tmp/contact | Modify a contact
*TmpApi* | [**modifyTmpContacts**](docs/TmpApi.md#modifytmpcontacts) | **PUT** /rest/v1/tmp/contact/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpDocument**](docs/TmpApi.md#modifytmpdocument) | **PUT** /rest/v1/tmp/document | Modify a document
*TmpApi* | [**modifyTmpDocuments**](docs/TmpApi.md#modifytmpdocuments) | **PUT** /rest/v1/tmp/document/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpEntityTemplate**](docs/TmpApi.md#modifytmpentitytemplate) | **PUT** /rest/v1/tmp/entityTemplate | Modify a entityTemplate
*TmpApi* | [**modifyTmpEntityTemplates**](docs/TmpApi.md#modifytmpentitytemplates) | **PUT** /rest/v1/tmp/entityTemplate/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpForm**](docs/TmpApi.md#modifytmpform) | **PUT** /rest/v1/tmp/form | Modify a form
*TmpApi* | [**modifyTmpForms**](docs/TmpApi.md#modifytmpforms) | **PUT** /rest/v1/tmp/form/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpHealthElement**](docs/TmpApi.md#modifytmphealthelement) | **PUT** /rest/v1/tmp/healthElement | Modify a healthElement
*TmpApi* | [**modifyTmpHealthElements**](docs/TmpApi.md#modifytmphealthelements) | **PUT** /rest/v1/tmp/healthElement/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpInvoice**](docs/TmpApi.md#modifytmpinvoice) | **PUT** /rest/v1/tmp/invoice | Modify a invoice
*TmpApi* | [**modifyTmpInvoices**](docs/TmpApi.md#modifytmpinvoices) | **PUT** /rest/v1/tmp/invoice/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpMessage**](docs/TmpApi.md#modifytmpmessage) | **PUT** /rest/v1/tmp/message | Modify a message
*TmpApi* | [**modifyTmpMessages**](docs/TmpApi.md#modifytmpmessages) | **PUT** /rest/v1/tmp/message/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpPatient**](docs/TmpApi.md#modifytmppatient) | **PUT** /rest/v1/tmp/patient | Modify a patient
*TmpApi* | [**modifyTmpPatients**](docs/TmpApi.md#modifytmppatients) | **PUT** /rest/v1/tmp/patient/batch | Modify a batch of healthcare elements
*TmpApi* | [**purgeTmpItems**](docs/TmpApi.md#purgetmpitems) | **POST** /rest/v1/tmp/batch/purge | Hard delete items.
*TmpApi* | [**replicateToTmpDatabase**](docs/TmpApi.md#replicatetotmpdatabase) | **POST** /rest/v1/tmp/replicate/from/{from} | 
*UserApi* | [**assignHealthcareParty**](docs/UserApi.md#assignhealthcareparty) | **PUT** /rest/v2/user/current/hcparty/{healthcarePartyId} | Assign a healthcare party ID to current user
*UserApi* | [**assignHealthcareParty1**](docs/UserApi.md#assignhealthcareparty1) | **PUT** /rest/v1/user/current/hcparty/{healthcarePartyId} | Assign a healthcare party ID to current user
*UserApi* | [**checkPassword**](docs/UserApi.md#checkpassword) | **GET** /rest/v2/user/checkPassword | 
*UserApi* | [**checkPassword1**](docs/UserApi.md#checkpassword1) | **GET** /rest/v1/user/checkPassword | 
*UserApi* | [**createUser**](docs/UserApi.md#createuser) | **POST** /rest/v2/user | Create a user
*UserApi* | [**createUser1**](docs/UserApi.md#createuser1) | **POST** /rest/v1/user | Create a user
*UserApi* | [**createUserInGroup**](docs/UserApi.md#createuseringroup) | **POST** /rest/v2/user/inGroup/{groupId} | Create a user
*UserApi* | [**createUserInGroup1**](docs/UserApi.md#createuseringroup1) | **POST** /rest/v1/user/inGroup/{groupId} | Create a user
*UserApi* | [**deleteUser**](docs/UserApi.md#deleteuser) | **DELETE** /rest/v2/user/{userId} | Delete a User based on his/her ID.
*UserApi* | [**deleteUser1**](docs/UserApi.md#deleteuser1) | **DELETE** /rest/v1/user/{userId} | Delete a User based on his/her ID.
*UserApi* | [**deleteUserInGroup**](docs/UserApi.md#deleteuseringroup) | **DELETE** /rest/v2/user/inGroup/{groupId}/{userId} | Delete a User based on his/her ID.
*UserApi* | [**deleteUserInGroup1**](docs/UserApi.md#deleteuseringroup1) | **DELETE** /rest/v1/user/inGroup/{groupId}/{userId} | Delete a User based on his/her ID.
*UserApi* | [**encodePassword**](docs/UserApi.md#encodepassword) | **GET** /rest/v2/user/encodePassword | 
*UserApi* | [**encodePassword1**](docs/UserApi.md#encodepassword1) | **GET** /rest/v1/user/encodePassword | 
*UserApi* | [**findByHcpartyId**](docs/UserApi.md#findbyhcpartyid) | **GET** /rest/v2/user/byHealthcarePartyId/{id} | Get the list of users by healthcare party id
*UserApi* | [**findByHcpartyId1**](docs/UserApi.md#findbyhcpartyid1) | **GET** /rest/v1/user/byHealthcarePartyId/{id} | Get the list of users by healthcare party id
*UserApi* | [**forgottenPassword**](docs/UserApi.md#forgottenpassword) | **POST** /rest/v2/user/forgottenPassword/{email} | Send a forgotten email message to an user
*UserApi* | [**forgottenPassword1**](docs/UserApi.md#forgottenpassword1) | **POST** /rest/v1/user/forgottenPassword/{email} | Send a forgotten email message to an user
*UserApi* | [**getCurrentSession**](docs/UserApi.md#getcurrentsession) | **GET** /rest/v2/user/session | Get Currently logged-in user session.
*UserApi* | [**getCurrentSession1**](docs/UserApi.md#getcurrentsession1) | **GET** /rest/v1/user/session | Get Currently logged-in user session.
*UserApi* | [**getCurrentUser**](docs/UserApi.md#getcurrentuser) | **GET** /rest/v2/user/current | Get presently logged-in user.
*UserApi* | [**getCurrentUser1**](docs/UserApi.md#getcurrentuser1) | **GET** /rest/v1/user/current | Get presently logged-in user.
*UserApi* | [**getMatchingUsers**](docs/UserApi.md#getmatchingusers) | **GET** /rest/v2/user/matches | Get presently logged-in user.
*UserApi* | [**getMatchingUsers1**](docs/UserApi.md#getmatchingusers1) | **GET** /rest/v1/user/matches | Get presently logged-in user.
*UserApi* | [**getUser**](docs/UserApi.md#getuser) | **GET** /rest/v2/user/{userId} | Get a user by his ID
*UserApi* | [**getUser1**](docs/UserApi.md#getuser1) | **GET** /rest/v1/user/{userId} | Get a user by his ID
*UserApi* | [**getUserByEmail**](docs/UserApi.md#getuserbyemail) | **GET** /rest/v2/user/byEmail/{email} | Get a user by his Email/Login
*UserApi* | [**getUserByEmail1**](docs/UserApi.md#getuserbyemail1) | **GET** /rest/v1/user/byEmail/{email} | Get a user by his Email/Login
*UserApi* | [**listUsers**](docs/UserApi.md#listusers) | **GET** /rest/v1/user | List users with(out) pagination
*UserApi* | [**listUsersBy**](docs/UserApi.md#listusersby) | **GET** /rest/v2/user | List users with(out) pagination
*UserApi* | [**listUsersInGroup**](docs/UserApi.md#listusersingroup) | **GET** /rest/v2/user/inGroup/{groupId} | List users with(out) pagination
*UserApi* | [**listUsersInGroup1**](docs/UserApi.md#listusersingroup1) | **GET** /rest/v1/user/inGroup/{groupId} | List users with(out) pagination
*UserApi* | [**modifyProperties**](docs/UserApi.md#modifyproperties) | **PUT** /rest/v2/user/{userId}/properties | Modify a User property
*UserApi* | [**modifyProperties1**](docs/UserApi.md#modifyproperties1) | **PUT** /rest/v1/user/{userId}/properties | Modify a User property
*UserApi* | [**modifyUser**](docs/UserApi.md#modifyuser) | **PUT** /rest/v2/user | Modify a user.
*UserApi* | [**modifyUser1**](docs/UserApi.md#modifyuser1) | **PUT** /rest/v1/user | Modify a user.
*UserApi* | [**modifyUserInGroup**](docs/UserApi.md#modifyuseringroup) | **PUT** /rest/v2/user/inGroup/{groupId} | Modify a user.
*UserApi* | [**modifyUserInGroup1**](docs/UserApi.md#modifyuseringroup1) | **PUT** /rest/v1/user/inGroup/{groupId} | Modify a user.


<a name="documentation-for-models"></a>
## Documentation for Models

 - [io.icure.kraken.client.models.AbstractFilterDtoCode](docs/AbstractFilterDtoCode.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoContact](docs/AbstractFilterDtoContact.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoHealthElement](docs/AbstractFilterDtoHealthElement.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoInvoice](docs/AbstractFilterDtoInvoice.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoPatient](docs/AbstractFilterDtoPatient.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoService](docs/AbstractFilterDtoService.md)
 - [io.icure.kraken.client.models.AccessLogDto](docs/AccessLogDto.md)
 - [io.icure.kraken.client.models.AddressDto](docs/AddressDto.md)
 - [io.icure.kraken.client.models.AdministrationQuantity](docs/AdministrationQuantity.md)
 - [io.icure.kraken.client.models.AgendaDto](docs/AgendaDto.md)
 - [io.icure.kraken.client.models.AgreementAppendixDto](docs/AgreementAppendixDto.md)
 - [io.icure.kraken.client.models.AmpComponentDto](docs/AmpComponentDto.md)
 - [io.icure.kraken.client.models.AmpDto](docs/AmpDto.md)
 - [io.icure.kraken.client.models.AmppComponentDto](docs/AmppComponentDto.md)
 - [io.icure.kraken.client.models.AmppDto](docs/AmppDto.md)
 - [io.icure.kraken.client.models.ApplicationSettingsDto](docs/ApplicationSettingsDto.md)
 - [io.icure.kraken.client.models.AppointmentDto](docs/AppointmentDto.md)
 - [io.icure.kraken.client.models.AppointmentImportDto](docs/AppointmentImportDto.md)
 - [io.icure.kraken.client.models.ArticleDto](docs/ArticleDto.md)
 - [io.icure.kraken.client.models.AtcDto](docs/AtcDto.md)
 - [io.icure.kraken.client.models.AuthenticationResponse](docs/AuthenticationResponse.md)
 - [io.icure.kraken.client.models.ByteArrayDto](docs/ByteArrayDto.md)
 - [io.icure.kraken.client.models.CalendarItemDto](docs/CalendarItemDto.md)
 - [io.icure.kraken.client.models.CalendarItemTagDto](docs/CalendarItemTagDto.md)
 - [io.icure.kraken.client.models.CalendarItemTypeDto](docs/CalendarItemTypeDto.md)
 - [io.icure.kraken.client.models.CareTeamMemberDto](docs/CareTeamMemberDto.md)
 - [io.icure.kraken.client.models.CareTeamMembershipDto](docs/CareTeamMembershipDto.md)
 - [io.icure.kraken.client.models.CheckSMFPatientResult](docs/CheckSMFPatientResult.md)
 - [io.icure.kraken.client.models.ClassificationDto](docs/ClassificationDto.md)
 - [io.icure.kraken.client.models.ClassificationTemplateDto](docs/ClassificationTemplateDto.md)
 - [io.icure.kraken.client.models.CodeDto](docs/CodeDto.md)
 - [io.icure.kraken.client.models.CodeStub](docs/CodeStub.md)
 - [io.icure.kraken.client.models.CodeStubDto](docs/CodeStubDto.md)
 - [io.icure.kraken.client.models.CommentedClassificationDto](docs/CommentedClassificationDto.md)
 - [io.icure.kraken.client.models.CommercializationDto](docs/CommercializationDto.md)
 - [io.icure.kraken.client.models.CompanyDto](docs/CompanyDto.md)
 - [io.icure.kraken.client.models.ContactDto](docs/ContactDto.md)
 - [io.icure.kraken.client.models.ContentDto](docs/ContentDto.md)
 - [io.icure.kraken.client.models.CopaymentDto](docs/CopaymentDto.md)
 - [io.icure.kraken.client.models.DatabaseInitialisationDto](docs/DatabaseInitialisationDto.md)
 - [io.icure.kraken.client.models.DatabaseSynchronizationDto](docs/DatabaseSynchronizationDto.md)
 - [io.icure.kraken.client.models.DelegationDto](docs/DelegationDto.md)
 - [io.icure.kraken.client.models.DeviceTypeDto](docs/DeviceTypeDto.md)
 - [io.icure.kraken.client.models.DiaryNoteExportInfoDto](docs/DiaryNoteExportInfoDto.md)
 - [io.icure.kraken.client.models.DmppDto](docs/DmppDto.md)
 - [io.icure.kraken.client.models.DocIdentifier](docs/DocIdentifier.md)
 - [io.icure.kraken.client.models.DocumentDto](docs/DocumentDto.md)
 - [io.icure.kraken.client.models.DocumentGroupDto](docs/DocumentGroupDto.md)
 - [io.icure.kraken.client.models.DocumentTemplateDto](docs/DocumentTemplateDto.md)
 - [io.icure.kraken.client.models.DurationDto](docs/DurationDto.md)
 - [io.icure.kraken.client.models.EIDItem](docs/EIDItem.md)
 - [io.icure.kraken.client.models.Editor](docs/Editor.md)
 - [io.icure.kraken.client.models.EfactInvoice](docs/EfactInvoice.md)
 - [io.icure.kraken.client.models.EmailOrSmsMessageDto](docs/EmailOrSmsMessageDto.md)
 - [io.icure.kraken.client.models.EmailTemplateDto](docs/EmailTemplateDto.md)
 - [io.icure.kraken.client.models.EmployerDto](docs/EmployerDto.md)
 - [io.icure.kraken.client.models.EmploymentInfoDto](docs/EmploymentInfoDto.md)
 - [io.icure.kraken.client.models.EntityReferenceDto](docs/EntityReferenceDto.md)
 - [io.icure.kraken.client.models.EntityTemplateDto](docs/EntityTemplateDto.md)
 - [io.icure.kraken.client.models.EpisodeDto](docs/EpisodeDto.md)
 - [io.icure.kraken.client.models.FilterChainCode](docs/FilterChainCode.md)
 - [io.icure.kraken.client.models.FilterChainContact](docs/FilterChainContact.md)
 - [io.icure.kraken.client.models.FilterChainHealthElement](docs/FilterChainHealthElement.md)
 - [io.icure.kraken.client.models.FilterChainInvoice](docs/FilterChainInvoice.md)
 - [io.icure.kraken.client.models.FilterChainPatient](docs/FilterChainPatient.md)
 - [io.icure.kraken.client.models.FilterChainService](docs/FilterChainService.md)
 - [io.icure.kraken.client.models.FinancialInstitutionInformationDto](docs/FinancialInstitutionInformationDto.md)
 - [io.icure.kraken.client.models.FlatRateTarificationDto](docs/FlatRateTarificationDto.md)
 - [io.icure.kraken.client.models.FlowItemDto](docs/FlowItemDto.md)
 - [io.icure.kraken.client.models.FormColumn](docs/FormColumn.md)
 - [io.icure.kraken.client.models.FormDataOption](docs/FormDataOption.md)
 - [io.icure.kraken.client.models.FormDto](docs/FormDto.md)
 - [io.icure.kraken.client.models.FormLayout](docs/FormLayout.md)
 - [io.icure.kraken.client.models.FormLayoutData](docs/FormLayoutData.md)
 - [io.icure.kraken.client.models.FormPlanning](docs/FormPlanning.md)
 - [io.icure.kraken.client.models.FormSection](docs/FormSection.md)
 - [io.icure.kraken.client.models.FormTemplateDto](docs/FormTemplateDto.md)
 - [io.icure.kraken.client.models.FormTemplateLayout](docs/FormTemplateLayout.md)
 - [io.icure.kraken.client.models.Formula](docs/Formula.md)
 - [io.icure.kraken.client.models.FrontEndMigrationDto](docs/FrontEndMigrationDto.md)
 - [io.icure.kraken.client.models.GroupDto](docs/GroupDto.md)
 - [io.icure.kraken.client.models.GuiCode](docs/GuiCode.md)
 - [io.icure.kraken.client.models.GuiCodeType](docs/GuiCodeType.md)
 - [io.icure.kraken.client.models.HealthElementDto](docs/HealthElementDto.md)
 - [io.icure.kraken.client.models.HealthcarePartyDto](docs/HealthcarePartyDto.md)
 - [io.icure.kraken.client.models.HealthcarePartyHistoryStatusDto](docs/HealthcarePartyHistoryStatusDto.md)
 - [io.icure.kraken.client.models.IcureStubDto](docs/IcureStubDto.md)
 - [io.icure.kraken.client.models.IdWithRevDto](docs/IdWithRevDto.md)
 - [io.icure.kraken.client.models.IdentifierDto](docs/IdentifierDto.md)
 - [io.icure.kraken.client.models.IdentityDocumentReaderDto](docs/IdentityDocumentReaderDto.md)
 - [io.icure.kraken.client.models.ImportMapping](docs/ImportMapping.md)
 - [io.icure.kraken.client.models.ImportResultDto](docs/ImportResultDto.md)
 - [io.icure.kraken.client.models.IndexingInfoDto](docs/IndexingInfoDto.md)
 - [io.icure.kraken.client.models.IngredientDto](docs/IngredientDto.md)
 - [io.icure.kraken.client.models.InlineObject10](docs/InlineObject10.md)
 - [io.icure.kraken.client.models.InlineObject11](docs/InlineObject11.md)
 - [io.icure.kraken.client.models.InlineObject12](docs/InlineObject12.md)
 - [io.icure.kraken.client.models.InlineObject13](docs/InlineObject13.md)
 - [io.icure.kraken.client.models.InlineObject14](docs/InlineObject14.md)
 - [io.icure.kraken.client.models.InlineObject15](docs/InlineObject15.md)
 - [io.icure.kraken.client.models.InlineObject16](docs/InlineObject16.md)
 - [io.icure.kraken.client.models.InlineObject17](docs/InlineObject17.md)
 - [io.icure.kraken.client.models.InlineObject18](docs/InlineObject18.md)
 - [io.icure.kraken.client.models.InlineObject19](docs/InlineObject19.md)
 - [io.icure.kraken.client.models.InlineObject20](docs/InlineObject20.md)
 - [io.icure.kraken.client.models.InlineObject21](docs/InlineObject21.md)
 - [io.icure.kraken.client.models.InlineObject22](docs/InlineObject22.md)
 - [io.icure.kraken.client.models.InlineObject23](docs/InlineObject23.md)
 - [io.icure.kraken.client.models.InlineObject24](docs/InlineObject24.md)
 - [io.icure.kraken.client.models.InlineObject25](docs/InlineObject25.md)
 - [io.icure.kraken.client.models.InlineObject26](docs/InlineObject26.md)
 - [io.icure.kraken.client.models.InlineObject27](docs/InlineObject27.md)
 - [io.icure.kraken.client.models.InlineObject28](docs/InlineObject28.md)
 - [io.icure.kraken.client.models.InlineObject29](docs/InlineObject29.md)
 - [io.icure.kraken.client.models.InlineObject30](docs/InlineObject30.md)
 - [io.icure.kraken.client.models.InlineObject31](docs/InlineObject31.md)
 - [io.icure.kraken.client.models.InlineObject32](docs/InlineObject32.md)
 - [io.icure.kraken.client.models.InlineObject33](docs/InlineObject33.md)
 - [io.icure.kraken.client.models.InlineObject34](docs/InlineObject34.md)
 - [io.icure.kraken.client.models.InlineObject35](docs/InlineObject35.md)
 - [io.icure.kraken.client.models.InlineObject36](docs/InlineObject36.md)
 - [io.icure.kraken.client.models.InlineObject37](docs/InlineObject37.md)
 - [io.icure.kraken.client.models.InlineObject38](docs/InlineObject38.md)
 - [io.icure.kraken.client.models.InlineObject39](docs/InlineObject39.md)
 - [io.icure.kraken.client.models.InlineObject4](docs/InlineObject4.md)
 - [io.icure.kraken.client.models.InlineObject40](docs/InlineObject40.md)
 - [io.icure.kraken.client.models.InlineObject41](docs/InlineObject41.md)
 - [io.icure.kraken.client.models.InlineObject42](docs/InlineObject42.md)
 - [io.icure.kraken.client.models.InlineObject43](docs/InlineObject43.md)
 - [io.icure.kraken.client.models.InlineObject44](docs/InlineObject44.md)
 - [io.icure.kraken.client.models.InlineObject45](docs/InlineObject45.md)
 - [io.icure.kraken.client.models.InlineObject46](docs/InlineObject46.md)
 - [io.icure.kraken.client.models.InlineObject47](docs/InlineObject47.md)
 - [io.icure.kraken.client.models.InlineObject48](docs/InlineObject48.md)
 - [io.icure.kraken.client.models.InlineObject49](docs/InlineObject49.md)
 - [io.icure.kraken.client.models.InlineObject5](docs/InlineObject5.md)
 - [io.icure.kraken.client.models.InlineObject50](docs/InlineObject50.md)
 - [io.icure.kraken.client.models.InlineObject51](docs/InlineObject51.md)
 - [io.icure.kraken.client.models.InlineObject52](docs/InlineObject52.md)
 - [io.icure.kraken.client.models.InlineObject53](docs/InlineObject53.md)
 - [io.icure.kraken.client.models.InlineObject54](docs/InlineObject54.md)
 - [io.icure.kraken.client.models.InlineObject55](docs/InlineObject55.md)
 - [io.icure.kraken.client.models.InlineObject56](docs/InlineObject56.md)
 - [io.icure.kraken.client.models.InlineObject57](docs/InlineObject57.md)
 - [io.icure.kraken.client.models.InlineObject58](docs/InlineObject58.md)
 - [io.icure.kraken.client.models.InlineObject59](docs/InlineObject59.md)
 - [io.icure.kraken.client.models.InlineObject6](docs/InlineObject6.md)
 - [io.icure.kraken.client.models.InlineObject60](docs/InlineObject60.md)
 - [io.icure.kraken.client.models.InlineObject61](docs/InlineObject61.md)
 - [io.icure.kraken.client.models.InlineObject62](docs/InlineObject62.md)
 - [io.icure.kraken.client.models.InlineObject63](docs/InlineObject63.md)
 - [io.icure.kraken.client.models.InlineObject64](docs/InlineObject64.md)
 - [io.icure.kraken.client.models.InlineObject65](docs/InlineObject65.md)
 - [io.icure.kraken.client.models.InlineObject66](docs/InlineObject66.md)
 - [io.icure.kraken.client.models.InlineObject67](docs/InlineObject67.md)
 - [io.icure.kraken.client.models.InlineObject68](docs/InlineObject68.md)
 - [io.icure.kraken.client.models.InlineObject69](docs/InlineObject69.md)
 - [io.icure.kraken.client.models.InlineObject7](docs/InlineObject7.md)
 - [io.icure.kraken.client.models.InlineObject70](docs/InlineObject70.md)
 - [io.icure.kraken.client.models.InlineObject71](docs/InlineObject71.md)
 - [io.icure.kraken.client.models.InlineObject72](docs/InlineObject72.md)
 - [io.icure.kraken.client.models.InlineObject73](docs/InlineObject73.md)
 - [io.icure.kraken.client.models.InlineObject74](docs/InlineObject74.md)
 - [io.icure.kraken.client.models.InlineObject75](docs/InlineObject75.md)
 - [io.icure.kraken.client.models.InlineObject76](docs/InlineObject76.md)
 - [io.icure.kraken.client.models.InlineObject77](docs/InlineObject77.md)
 - [io.icure.kraken.client.models.InlineObject78](docs/InlineObject78.md)
 - [io.icure.kraken.client.models.InlineObject79](docs/InlineObject79.md)
 - [io.icure.kraken.client.models.InlineObject8](docs/InlineObject8.md)
 - [io.icure.kraken.client.models.InlineObject80](docs/InlineObject80.md)
 - [io.icure.kraken.client.models.InlineObject81](docs/InlineObject81.md)
 - [io.icure.kraken.client.models.InlineObject82](docs/InlineObject82.md)
 - [io.icure.kraken.client.models.InlineObject83](docs/InlineObject83.md)
 - [io.icure.kraken.client.models.InlineObject84](docs/InlineObject84.md)
 - [io.icure.kraken.client.models.InlineObject85](docs/InlineObject85.md)
 - [io.icure.kraken.client.models.InlineObject86](docs/InlineObject86.md)
 - [io.icure.kraken.client.models.InlineObject87](docs/InlineObject87.md)
 - [io.icure.kraken.client.models.InlineObject88](docs/InlineObject88.md)
 - [io.icure.kraken.client.models.InlineObject89](docs/InlineObject89.md)
 - [io.icure.kraken.client.models.InlineObject9](docs/InlineObject9.md)
 - [io.icure.kraken.client.models.InlineObject90](docs/InlineObject90.md)
 - [io.icure.kraken.client.models.InlineObject91](docs/InlineObject91.md)
 - [io.icure.kraken.client.models.InlineObject92](docs/InlineObject92.md)
 - [io.icure.kraken.client.models.InlineObject93](docs/InlineObject93.md)
 - [io.icure.kraken.client.models.InlineObject94](docs/InlineObject94.md)
 - [io.icure.kraken.client.models.InlineObject95](docs/InlineObject95.md)
 - [io.icure.kraken.client.models.InlineObject96](docs/InlineObject96.md)
 - [io.icure.kraken.client.models.InlineObject97](docs/InlineObject97.md)
 - [io.icure.kraken.client.models.InlineObject98](docs/InlineObject98.md)
 - [io.icure.kraken.client.models.InlineObject99](docs/InlineObject99.md)
 - [io.icure.kraken.client.models.InsurabilityDto](docs/InsurabilityDto.md)
 - [io.icure.kraken.client.models.InsuranceDto](docs/InsuranceDto.md)
 - [io.icure.kraken.client.models.InvoiceDto](docs/InvoiceDto.md)
 - [io.icure.kraken.client.models.InvoiceItem](docs/InvoiceItem.md)
 - [io.icure.kraken.client.models.InvoiceSender](docs/InvoiceSender.md)
 - [io.icure.kraken.client.models.InvoicesBatch](docs/InvoicesBatch.md)
 - [io.icure.kraken.client.models.InvoicingCodeDto](docs/InvoicingCodeDto.md)
 - [io.icure.kraken.client.models.KeywordDto](docs/KeywordDto.md)
 - [io.icure.kraken.client.models.KeywordSubwordDto](docs/KeywordSubwordDto.md)
 - [io.icure.kraken.client.models.LabelledOccurenceDto](docs/LabelledOccurenceDto.md)
 - [io.icure.kraken.client.models.LetterValueDto](docs/LetterValueDto.md)
 - [io.icure.kraken.client.models.ListOfIdsDto](docs/ListOfIdsDto.md)
 - [io.icure.kraken.client.models.ListOfPropertiesDto](docs/ListOfPropertiesDto.md)
 - [io.icure.kraken.client.models.MapOfIdsDto](docs/MapOfIdsDto.md)
 - [io.icure.kraken.client.models.MeasureDto](docs/MeasureDto.md)
 - [io.icure.kraken.client.models.MedexInfoDto](docs/MedexInfoDto.md)
 - [io.icure.kraken.client.models.MedicalHouseContractDto](docs/MedicalHouseContractDto.md)
 - [io.icure.kraken.client.models.MedicalLocationDto](docs/MedicalLocationDto.md)
 - [io.icure.kraken.client.models.MedicationDto](docs/MedicationDto.md)
 - [io.icure.kraken.client.models.MedicationSchemeExportInfoDto](docs/MedicationSchemeExportInfoDto.md)
 - [io.icure.kraken.client.models.MedicinalproductDto](docs/MedicinalproductDto.md)
 - [io.icure.kraken.client.models.MessageDto](docs/MessageDto.md)
 - [io.icure.kraken.client.models.MessageReadStatusDto](docs/MessageReadStatusDto.md)
 - [io.icure.kraken.client.models.MessageWithBatch](docs/MessageWithBatch.md)
 - [io.icure.kraken.client.models.MessagesReadStatusUpdate](docs/MessagesReadStatusUpdate.md)
 - [io.icure.kraken.client.models.MikronoAppointmentTypeRestDto](docs/MikronoAppointmentTypeRestDto.md)
 - [io.icure.kraken.client.models.MikronoCredentialsDto](docs/MikronoCredentialsDto.md)
 - [io.icure.kraken.client.models.MimeAttachmentDto](docs/MimeAttachmentDto.md)
 - [io.icure.kraken.client.models.NmpDto](docs/NmpDto.md)
 - [io.icure.kraken.client.models.NoGenericPrescriptionReasonDto](docs/NoGenericPrescriptionReasonDto.md)
 - [io.icure.kraken.client.models.NoSwitchReasonDto](docs/NoSwitchReasonDto.md)
 - [io.icure.kraken.client.models.NumeratorRangeDto](docs/NumeratorRangeDto.md)
 - [io.icure.kraken.client.models.PackagingTypeDto](docs/PackagingTypeDto.md)
 - [io.icure.kraken.client.models.PaginatedDocumentKeyIdPairObject](docs/PaginatedDocumentKeyIdPairObject.md)
 - [io.icure.kraken.client.models.PaginatedListAccessLogDto](docs/PaginatedListAccessLogDto.md)
 - [io.icure.kraken.client.models.PaginatedListAmpDto](docs/PaginatedListAmpDto.md)
 - [io.icure.kraken.client.models.PaginatedListClassificationDto](docs/PaginatedListClassificationDto.md)
 - [io.icure.kraken.client.models.PaginatedListClassificationTemplateDto](docs/PaginatedListClassificationTemplateDto.md)
 - [io.icure.kraken.client.models.PaginatedListCodeDto](docs/PaginatedListCodeDto.md)
 - [io.icure.kraken.client.models.PaginatedListContactDto](docs/PaginatedListContactDto.md)
 - [io.icure.kraken.client.models.PaginatedListDocumentDto](docs/PaginatedListDocumentDto.md)
 - [io.icure.kraken.client.models.PaginatedListEntityTemplateDto](docs/PaginatedListEntityTemplateDto.md)
 - [io.icure.kraken.client.models.PaginatedListFormDto](docs/PaginatedListFormDto.md)
 - [io.icure.kraken.client.models.PaginatedListHealthElementDto](docs/PaginatedListHealthElementDto.md)
 - [io.icure.kraken.client.models.PaginatedListHealthcarePartyDto](docs/PaginatedListHealthcarePartyDto.md)
 - [io.icure.kraken.client.models.PaginatedListInvoiceDto](docs/PaginatedListInvoiceDto.md)
 - [io.icure.kraken.client.models.PaginatedListMessageDto](docs/PaginatedListMessageDto.md)
 - [io.icure.kraken.client.models.PaginatedListNmpDto](docs/PaginatedListNmpDto.md)
 - [io.icure.kraken.client.models.PaginatedListPatientDto](docs/PaginatedListPatientDto.md)
 - [io.icure.kraken.client.models.PaginatedListSerializable](docs/PaginatedListSerializable.md)
 - [io.icure.kraken.client.models.PaginatedListServiceDto](docs/PaginatedListServiceDto.md)
 - [io.icure.kraken.client.models.PaginatedListString](docs/PaginatedListString.md)
 - [io.icure.kraken.client.models.PaginatedListTarificationDto](docs/PaginatedListTarificationDto.md)
 - [io.icure.kraken.client.models.PaginatedListUserDto](docs/PaginatedListUserDto.md)
 - [io.icure.kraken.client.models.PaginatedListVmpDto](docs/PaginatedListVmpDto.md)
 - [io.icure.kraken.client.models.PaginatedListVmpGroupDto](docs/PaginatedListVmpGroupDto.md)
 - [io.icure.kraken.client.models.ParagraphAgreementDto](docs/ParagraphAgreementDto.md)
 - [io.icure.kraken.client.models.PartnershipDto](docs/PartnershipDto.md)
 - [io.icure.kraken.client.models.PatientDto](docs/PatientDto.md)
 - [io.icure.kraken.client.models.PatientHealthCarePartyDto](docs/PatientHealthCarePartyDto.md)
 - [io.icure.kraken.client.models.PaymentDto](docs/PaymentDto.md)
 - [io.icure.kraken.client.models.PeriodicityDto](docs/PeriodicityDto.md)
 - [io.icure.kraken.client.models.PermissionDto](docs/PermissionDto.md)
 - [io.icure.kraken.client.models.PermissionItemDto](docs/PermissionItemDto.md)
 - [io.icure.kraken.client.models.PharmaceuticalFormDto](docs/PharmaceuticalFormDto.md)
 - [io.icure.kraken.client.models.PharmaceuticalFormStubDto](docs/PharmaceuticalFormStubDto.md)
 - [io.icure.kraken.client.models.PlaceDto](docs/PlaceDto.md)
 - [io.icure.kraken.client.models.PlanOfActionDto](docs/PlanOfActionDto.md)
 - [io.icure.kraken.client.models.PricingDto](docs/PricingDto.md)
 - [io.icure.kraken.client.models.PropertyStubDto](docs/PropertyStubDto.md)
 - [io.icure.kraken.client.models.PropertyTypeStubDto](docs/PropertyTypeStubDto.md)
 - [io.icure.kraken.client.models.PublicKeyDto](docs/PublicKeyDto.md)
 - [io.icure.kraken.client.models.QuantityDto](docs/QuantityDto.md)
 - [io.icure.kraken.client.models.ReceiptDto](docs/ReceiptDto.md)
 - [io.icure.kraken.client.models.ReferralPeriodDto](docs/ReferralPeriodDto.md)
 - [io.icure.kraken.client.models.RegimenItemDto](docs/RegimenItemDto.md)
 - [io.icure.kraken.client.models.RegistrationInformationDto](docs/RegistrationInformationDto.md)
 - [io.icure.kraken.client.models.RegistrationSuccessDto](docs/RegistrationSuccessDto.md)
 - [io.icure.kraken.client.models.ReimbursementCriterionDto](docs/ReimbursementCriterionDto.md)
 - [io.icure.kraken.client.models.ReimbursementDto](docs/ReimbursementDto.md)
 - [io.icure.kraken.client.models.RenewalDto](docs/RenewalDto.md)
 - [io.icure.kraken.client.models.ReplicationDto](docs/ReplicationDto.md)
 - [io.icure.kraken.client.models.ReplicationInfoDto](docs/ReplicationInfoDto.md)
 - [io.icure.kraken.client.models.ReplicationStats](docs/ReplicationStats.md)
 - [io.icure.kraken.client.models.ReplicatorDocument](docs/ReplicatorDocument.md)
 - [io.icure.kraken.client.models.ResultInfoDto](docs/ResultInfoDto.md)
 - [io.icure.kraken.client.models.RightDto](docs/RightDto.md)
 - [io.icure.kraken.client.models.RouteOfAdministrationDto](docs/RouteOfAdministrationDto.md)
 - [io.icure.kraken.client.models.SamTextDto](docs/SamTextDto.md)
 - [io.icure.kraken.client.models.SamVersionDto](docs/SamVersionDto.md)
 - [io.icure.kraken.client.models.SchoolingInfoDto](docs/SchoolingInfoDto.md)
 - [io.icure.kraken.client.models.Section](docs/Section.md)
 - [io.icure.kraken.client.models.ServiceDto](docs/ServiceDto.md)
 - [io.icure.kraken.client.models.ServiceLinkDto](docs/ServiceLinkDto.md)
 - [io.icure.kraken.client.models.SoftwareMedicalFileExportDto](docs/SoftwareMedicalFileExportDto.md)
 - [io.icure.kraken.client.models.StandardSubstanceDto](docs/StandardSubstanceDto.md)
 - [io.icure.kraken.client.models.StrengthRangeDto](docs/StrengthRangeDto.md)
 - [io.icure.kraken.client.models.SubContactDto](docs/SubContactDto.md)
 - [io.icure.kraken.client.models.SubstanceDto](docs/SubstanceDto.md)
 - [io.icure.kraken.client.models.SubstanceStubDto](docs/SubstanceStubDto.md)
 - [io.icure.kraken.client.models.SubstanceproductDto](docs/SubstanceproductDto.md)
 - [io.icure.kraken.client.models.Suggest](docs/Suggest.md)
 - [io.icure.kraken.client.models.SumehrContentDto](docs/SumehrContentDto.md)
 - [io.icure.kraken.client.models.SumehrExportInfoDto](docs/SumehrExportInfoDto.md)
 - [io.icure.kraken.client.models.SumehrValidityDto](docs/SumehrValidityDto.md)
 - [io.icure.kraken.client.models.SupplyProblemDto](docs/SupplyProblemDto.md)
 - [io.icure.kraken.client.models.SuspensionDto](docs/SuspensionDto.md)
 - [io.icure.kraken.client.models.Tag](docs/Tag.md)
 - [io.icure.kraken.client.models.TarificationDto](docs/TarificationDto.md)
 - [io.icure.kraken.client.models.TelecomDto](docs/TelecomDto.md)
 - [io.icure.kraken.client.models.TimeTableDto](docs/TimeTableDto.md)
 - [io.icure.kraken.client.models.TimeTableHourDto](docs/TimeTableHourDto.md)
 - [io.icure.kraken.client.models.TimeTableItemDto](docs/TimeTableItemDto.md)
 - [io.icure.kraken.client.models.TypedValueDtoObject](docs/TypedValueDtoObject.md)
 - [io.icure.kraken.client.models.UserDto](docs/UserDto.md)
 - [io.icure.kraken.client.models.UserGroupDto](docs/UserGroupDto.md)
 - [io.icure.kraken.client.models.ValorisationDto](docs/ValorisationDto.md)
 - [io.icure.kraken.client.models.VirtualFormDto](docs/VirtualFormDto.md)
 - [io.icure.kraken.client.models.VirtualIngredientDto](docs/VirtualIngredientDto.md)
 - [io.icure.kraken.client.models.VmpComponentDto](docs/VmpComponentDto.md)
 - [io.icure.kraken.client.models.VmpDto](docs/VmpDto.md)
 - [io.icure.kraken.client.models.VmpGroupDto](docs/VmpGroupDto.md)
 - [io.icure.kraken.client.models.VmpGroupStubDto](docs/VmpGroupStubDto.md)
 - [io.icure.kraken.client.models.VmpStubDto](docs/VmpStubDto.md)
 - [io.icure.kraken.client.models.VtmDto](docs/VtmDto.md)
 - [io.icure.kraken.client.models.WadaDto](docs/WadaDto.md)
 - [io.icure.kraken.client.models.WebSession](docs/WebSession.md)
 - [io.icure.kraken.client.models.WebSessionMaxIdleTime](docs/WebSessionMaxIdleTime.md)
 - [io.icure.kraken.client.models.WebSessionMaxIdleTimeUnits](docs/WebSessionMaxIdleTimeUnits.md)
 - [io.icure.kraken.client.models.Weekday](docs/Weekday.md)


<a name="documentation-for-authorization"></a>
## Documentation for Authorization

All endpoints do not require authorization.
