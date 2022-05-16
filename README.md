# io.icure.kraken.client - Kotlin client library for iCure Data Stack API Documentation

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
*AccessLogApi* | [**createAccessLog**](docs/AccessLogApi.md#createaccesslog) | **POST** /rest/v2/accesslog | Creates an access log
*AccessLogApi* | [**deleteAccessLogs**](docs/AccessLogApi.md#deleteaccesslogs) | **POST** /rest/v2/accesslog/delete/batch | Deletes an access log
*AccessLogApi* | [**findAccessLogsBy**](docs/AccessLogApi.md#findaccesslogsby) | **GET** /rest/v2/accesslog | Get Paginated List of Access logs
*AccessLogApi* | [**findAccessLogsByUserAfterDate**](docs/AccessLogApi.md#findaccesslogsbyuserafterdate) | **GET** /rest/v2/accesslog/byUser | Get Paginated List of Access logs by user after date
*AccessLogApi* | [**getAccessLog**](docs/AccessLogApi.md#getaccesslog) | **GET** /rest/v2/accesslog/{accessLogId} | Gets an access log
*AccessLogApi* | [**listAccessLogsByHCPartyAndPatientForeignKeys**](docs/AccessLogApi.md#listaccesslogsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/accesslog/byHcPartySecretForeignKeys | List access logs found By Healthcare Party and secret foreign keyelementIds.
*AccessLogApi* | [**modifyAccessLog**](docs/AccessLogApi.md#modifyaccesslog) | **PUT** /rest/v2/accesslog | Modifies an access log
*AgendaApi* | [**createAgenda**](docs/AgendaApi.md#createagenda) | **POST** /rest/v2/agenda | Creates a agenda
*AgendaApi* | [**deleteAgendas**](docs/AgendaApi.md#deleteagendas) | **POST** /rest/v2/agenda/delete/batch | Deletes agendas
*AgendaApi* | [**getAgenda**](docs/AgendaApi.md#getagenda) | **GET** /rest/v2/agenda/{agendaId} | Gets an agenda
*AgendaApi* | [**getAgendas**](docs/AgendaApi.md#getagendas) | **GET** /rest/v2/agenda | Gets all agendas
*AgendaApi* | [**getAgendasForUser**](docs/AgendaApi.md#getagendasforuser) | **GET** /rest/v2/agenda/byUser | Gets all agendas for user
*AgendaApi* | [**getReadableAgendasForUser**](docs/AgendaApi.md#getreadableagendasforuser) | **GET** /rest/v2/agenda/readableForUser | Gets readable agendas for user
*AgendaApi* | [**modifyAgenda**](docs/AgendaApi.md#modifyagenda) | **PUT** /rest/v2/agenda | Modifies an agenda
*AnonymousAccessApi* | [**getAvailabilitiesByPeriodAndCalendarItemTypeId**](docs/AnonymousAccessApi.md#getavailabilitiesbyperiodandcalendaritemtypeid) | **GET** /rest/v2/aa/available/inGroup/{groupId}/forUser/{userId}/type/{calendarItemTypeId} | Get Availabilities for HCP and appointmentType
*AnonymousAccessApi* | [**listAppointmentTypesForUser**](docs/AnonymousAccessApi.md#listappointmenttypesforuser) | **GET** /rest/v2/aa/appointmentType/inGroup/{groupId}/forUser/{userId} | List Calendar Item types for a provided group id and user id
*AnonymousAccessApi* | [**listHealthcarePartiesInGroup**](docs/AnonymousAccessApi.md#listhealthcarepartiesingroup) | **GET** /rest/v2/aa/hcparty/inGroup/{groupId} | List healthcare parties for a provided group id
*ApplicationsettingsApi* | [**createApplicationSettings**](docs/ApplicationsettingsApi.md#createapplicationsettings) | **POST** /rest/v2/appsettings | Create new application settings
*ApplicationsettingsApi* | [**getApplicationSettings**](docs/ApplicationsettingsApi.md#getapplicationsettings) | **GET** /rest/v2/appsettings | Gets all application settings
*ArticleApi* | [**createArticle**](docs/ArticleApi.md#createarticle) | **POST** /rest/v2/article | Creates a article
*ArticleApi* | [**deleteArticles**](docs/ArticleApi.md#deletearticles) | **POST** /rest/v2/article/delete/batch | Deletes articles
*ArticleApi* | [**getArticle**](docs/ArticleApi.md#getarticle) | **GET** /rest/v2/article/{articleId} | Gets an article
*ArticleApi* | [**getArticles**](docs/ArticleApi.md#getarticles) | **GET** /rest/v2/article | Gets all articles
*ArticleApi* | [**modifyArticle**](docs/ArticleApi.md#modifyarticle) | **PUT** /rest/v2/article | Modifies an article
*AuthApi* | [**login**](docs/AuthApi.md#login) | **POST** /rest/v2/auth/login | login
*AuthApi* | [**logout**](docs/AuthApi.md#logout) | **GET** /rest/v2/auth/logout | logout
*AuthApi* | [**logoutPost**](docs/AuthApi.md#logoutpost) | **POST** /rest/v2/auth/logout | logout
*AuthApi* | [**token**](docs/AuthApi.md#token) | **GET** /rest/v2/auth/token/{method}/{path} | token
*BeefactApi* | [**createBatchAndMessage**](docs/BeefactApi.md#createbatchandmessage) | **POST** /rest/v2/be_efact/{insuranceId}/{newMessageId}/{numericalRef} | create batch and message
*BekmehrApi* | [**checkIfSMFPatientsExists**](docs/BekmehrApi.md#checkifsmfpatientsexists) | **POST** /rest/v2/be_kmehr/smf/{documentId}/checkIfSMFPatientsExists | Check whether patients in SMF already exists in DB
*BekmehrApi* | [**generateContactreportExport**](docs/BekmehrApi.md#generatecontactreportexport) | **POST** /rest/v2/be_kmehr/contactreport/{patientId}/export/{id} | Get Kmehr contactreport
*BekmehrApi* | [**generateDiaryNote**](docs/BekmehrApi.md#generatediarynote) | **POST** /rest/v2/be_kmehr/diarynote/{patientId}/export | Generate diarynote
*BekmehrApi* | [**generateIncapacityExport**](docs/BekmehrApi.md#generateincapacityexport) | **POST** /rest/v2/be_kmehr/incapacity/{patientId}/export | Get Incapacity export
*BekmehrApi* | [**generateLabresultExport**](docs/BekmehrApi.md#generatelabresultexport) | **POST** /rest/v2/be_kmehr/labresult/{patientId}/export/{id} | Get Kmehr labresult
*BekmehrApi* | [**generateMedicationSchemeExport**](docs/BekmehrApi.md#generatemedicationschemeexport) | **POST** /rest/v2/be_kmehr/medicationscheme/{patientId}/export | Get Medicationscheme export
*BekmehrApi* | [**generateNoteExport**](docs/BekmehrApi.md#generatenoteexport) | **POST** /rest/v2/be_kmehr/note/{patientId}/export/{id} | Get Kmehr note
*BekmehrApi* | [**generatePatientInfoExport**](docs/BekmehrApi.md#generatepatientinfoexport) | **POST** /rest/v2/be_kmehr/patientinfo/{patientId}/export | Get KMEHR Patient Info export
*BekmehrApi* | [**generatePrescriptionExport**](docs/BekmehrApi.md#generateprescriptionexport) | **POST** /rest/v2/be_kmehr/prescription/{patientId}/export/{id} | Get Kmehr prescription
*BekmehrApi* | [**generateReportExport**](docs/BekmehrApi.md#generatereportexport) | **POST** /rest/v2/be_kmehr/report/{patientId}/export/{id} | Get Kmehr report
*BekmehrApi* | [**generateRequestExport**](docs/BekmehrApi.md#generaterequestexport) | **POST** /rest/v2/be_kmehr/request/{patientId}/export/{id} | Get Kmehr request
*BekmehrApi* | [**generateResultExport**](docs/BekmehrApi.md#generateresultexport) | **POST** /rest/v2/be_kmehr/result/{patientId}/export/{id} | Get Kmehr result
*BekmehrApi* | [**generateSmfExport**](docs/BekmehrApi.md#generatesmfexport) | **POST** /rest/v2/be_kmehr/smf/{patientId}/export | Get SMF (Software Medical File) export
*BekmehrApi* | [**generateSumehr**](docs/BekmehrApi.md#generatesumehr) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/export | Generate sumehr
*BekmehrApi* | [**generateSumehrV2**](docs/BekmehrApi.md#generatesumehrv2) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/export | Generate sumehr
*BekmehrApi* | [**getSumehrContent**](docs/BekmehrApi.md#getsumehrcontent) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/content | Get sumehr elements
*BekmehrApi* | [**getSumehrMd5**](docs/BekmehrApi.md#getsumehrmd5) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/md5 | Check sumehr signature
*BekmehrApi* | [**getSumehrV2Content**](docs/BekmehrApi.md#getsumehrv2content) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/content | Get sumehr elements
*BekmehrApi* | [**getSumehrV2Md5**](docs/BekmehrApi.md#getsumehrv2md5) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/md5 | Check sumehr signature
*BekmehrApi* | [**importMedicationScheme**](docs/BekmehrApi.md#importmedicationscheme) | **POST** /rest/v2/be_kmehr/medicationscheme/{documentId}/import | Import MedicationScheme into patient(s) using existing document
*BekmehrApi* | [**importSmf**](docs/BekmehrApi.md#importsmf) | **POST** /rest/v2/be_kmehr/smf/{documentId}/import | Import SMF into patient(s) using existing document
*BekmehrApi* | [**importSumehr**](docs/BekmehrApi.md#importsumehr) | **POST** /rest/v2/be_kmehr/sumehr/{documentId}/import | Import sumehr into patient(s) using existing document
*BekmehrApi* | [**importSumehrByItemId**](docs/BekmehrApi.md#importsumehrbyitemid) | **POST** /rest/v2/be_kmehr/sumehr/{documentId}/importbyitemid | Import sumehr into patient(s) using existing document
*BekmehrApi* | [**isSumehrV2Valid**](docs/BekmehrApi.md#issumehrv2valid) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/valid | Get sumehr validity
*BekmehrApi* | [**isSumehrValid**](docs/BekmehrApi.md#issumehrvalid) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/valid | Get sumehr validity
*BekmehrApi* | [**validateSumehr**](docs/BekmehrApi.md#validatesumehr) | **POST** /rest/v2/be_kmehr/sumehr/{patientId}/validate | Validate sumehr
*BekmehrApi* | [**validateSumehrV2**](docs/BekmehrApi.md#validatesumehrv2) | **POST** /rest/v2/be_kmehr/sumehrv2/{patientId}/validate | Validate sumehr
*BeresultexportApi* | [**exportHealthOne**](docs/BeresultexportApi.md#exporthealthone) | **POST** /rest/v2/be_result_export/hl1/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
*BeresultexportApi* | [**exportKmehrReport**](docs/BeresultexportApi.md#exportkmehrreport) | **POST** /rest/v2/be_result_export/kmehrreport/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
*BeresultexportApi* | [**exportMedidoc**](docs/BeresultexportApi.md#exportmedidoc) | **POST** /rest/v2/be_result_export/medidoc/{fromHcpId}/{toHcpId}/{patId}/{date}/{ref} | Export data
*BeresultimportApi* | [**canHandle**](docs/BeresultimportApi.md#canhandle) | **GET** /rest/v2/be_result_import/canhandle/{id} | Can we handle this document
*BeresultimportApi* | [**doImport**](docs/BeresultimportApi.md#doimport) | **POST** /rest/v2/be_result_import/import/{documentId}/{hcpId}/{language} | import document
*BeresultimportApi* | [**getInfos**](docs/BeresultimportApi.md#getinfos) | **GET** /rest/v2/be_result_import/infos/{id} | Extract general infos from document
*Besamv2Api* | [**findAmpsByDmppCode**](docs/Besamv2Api.md#findampsbydmppcode) | **GET** /rest/v2/be_samv2/amp/byDmppCode/{dmppCode} | Finding AMPs by dmpp code
*Besamv2Api* | [**findPaginatedAmpsByAtc**](docs/Besamv2Api.md#findpaginatedampsbyatc) | **GET** /rest/v2/be_samv2/vmp/byAtc/{atcCode} | Finding AMPs by atc code with pagination.
*Besamv2Api* | [**findPaginatedAmpsByGroupCode**](docs/Besamv2Api.md#findpaginatedampsbygroupcode) | **GET** /rest/v2/be_samv2/amp/byGroupCode/{vmpgCode} | Finding AMPs by group with pagination.
*Besamv2Api* | [**findPaginatedAmpsByGroupId**](docs/Besamv2Api.md#findpaginatedampsbygroupid) | **GET** /rest/v2/be_samv2/amp/byGroupId/{vmpgId} | Finding AMPs by group with pagination.
*Besamv2Api* | [**findPaginatedAmpsByLabel**](docs/Besamv2Api.md#findpaginatedampsbylabel) | **GET** /rest/v2/be_samv2/amp | Finding AMPs by label with pagination.
*Besamv2Api* | [**findPaginatedAmpsByVmpCode**](docs/Besamv2Api.md#findpaginatedampsbyvmpcode) | **GET** /rest/v2/be_samv2/amp/byVmpCode/{vmpCode} | Finding AMPs by vmp code with pagination.
*Besamv2Api* | [**findPaginatedAmpsByVmpId**](docs/Besamv2Api.md#findpaginatedampsbyvmpid) | **GET** /rest/v2/be_samv2/amp/byVmpId/{vmpId} | Finding AMPs by vmp id with pagination.
*Besamv2Api* | [**findPaginatedNmpsByLabel**](docs/Besamv2Api.md#findpaginatednmpsbylabel) | **GET** /rest/v2/be_samv2/nmp | Finding NMPs by label with pagination.
*Besamv2Api* | [**findPaginatedVmpGroupsByLabel**](docs/Besamv2Api.md#findpaginatedvmpgroupsbylabel) | **GET** /rest/v2/be_samv2/vmpgroup | Finding VMP groups by language label with pagination.
*Besamv2Api* | [**findPaginatedVmpGroupsByVmpGroupCode**](docs/Besamv2Api.md#findpaginatedvmpgroupsbyvmpgroupcode) | **GET** /rest/v2/be_samv2/vmpgroup/byGroupCode/{vmpgCode} | Finding VMP groups by cmpgCode with pagination.
*Besamv2Api* | [**findPaginatedVmpsByGroupCode**](docs/Besamv2Api.md#findpaginatedvmpsbygroupcode) | **GET** /rest/v2/be_samv2/vmp/byGroupCode/{vmpgCode} | Finding VMPs by group with pagination.
*Besamv2Api* | [**findPaginatedVmpsByGroupId**](docs/Besamv2Api.md#findpaginatedvmpsbygroupid) | **GET** /rest/v2/be_samv2/vmp/byGroupId/{vmpgId} | Finding VMPs by group with pagination.
*Besamv2Api* | [**findPaginatedVmpsByLabel**](docs/Besamv2Api.md#findpaginatedvmpsbylabel) | **GET** /rest/v2/be_samv2/vmp | Finding VMPs by label with pagination.
*Besamv2Api* | [**findPaginatedVmpsByVmpCode**](docs/Besamv2Api.md#findpaginatedvmpsbyvmpcode) | **GET** /rest/v2/be_samv2/vmp/byVmpCode/{vmpCode} | Finding VMPs by group with pagination.
*Besamv2Api* | [**findParagraphs**](docs/Besamv2Api.md#findparagraphs) | **GET** /rest/v2/be_samv2/chap/search/{searchString}/{language} | 
*Besamv2Api* | [**findParagraphsWithCnk**](docs/Besamv2Api.md#findparagraphswithcnk) | **GET** /rest/v2/be_samv2/chap/bycnk/{cnk}/{language} | 
*Besamv2Api* | [**getAddedDocument**](docs/Besamv2Api.md#getaddeddocument) | **GET** /rest/v2/be_samv2/chap/{chapterName}/{paragraphName}/{verseSeq}/addeddoc/{docSeq}/{language} | 
*Besamv2Api* | [**getAmpsForParagraph**](docs/Besamv2Api.md#getampsforparagraph) | **GET** /rest/v2/be_samv2/chap/amps/{chapterName}/{paragraphName} | 
*Besamv2Api* | [**getSamVersion**](docs/Besamv2Api.md#getsamversion) | **GET** /rest/v2/be_samv2/v | Get Samv2 version.
*Besamv2Api* | [**getVersesHierarchy**](docs/Besamv2Api.md#getverseshierarchy) | **GET** /rest/v2/be_samv2/chap/verse/{chapterName}/{paragraphName} | 
*Besamv2Api* | [**getVtmNamesForParagraph**](docs/Besamv2Api.md#getvtmnamesforparagraph) | **GET** /rest/v2/be_samv2/chap/vtms/{chapterName}/{paragraphName}/{language} | 
*Besamv2Api* | [**listAmpsByDmppCodes**](docs/Besamv2Api.md#listampsbydmppcodes) | **POST** /rest/v2/be_samv2/amp/byDmppCodes | Finding AMPs by dmpp code
*Besamv2Api* | [**listAmpsByGroupCodes**](docs/Besamv2Api.md#listampsbygroupcodes) | **POST** /rest/v2/be_samv2/amp/byGroupCodes | Finding AMPs by group.
*Besamv2Api* | [**listAmpsByGroupIds**](docs/Besamv2Api.md#listampsbygroupids) | **POST** /rest/v2/be_samv2/amp/byGroupIds | Finding AMPs by group.
*Besamv2Api* | [**listAmpsByVmpCodes**](docs/Besamv2Api.md#listampsbyvmpcodes) | **POST** /rest/v2/be_samv2/amp/byVmpCodes | Finding AMPs by vmp code.
*Besamv2Api* | [**listAmpsByVmpIds**](docs/Besamv2Api.md#listampsbyvmpids) | **POST** /rest/v2/be_samv2/amp/byVmpIds | Finding AMPs by vmp id.
*Besamv2Api* | [**listNmpsByCnks**](docs/Besamv2Api.md#listnmpsbycnks) | **POST** /rest/v2/be_samv2/nmp/byCnks | Finding NMPs by cnk id.
*Besamv2Api* | [**listPharmaceuticalForms**](docs/Besamv2Api.md#listpharmaceuticalforms) | **GET** /rest/v2/be_samv2/pharmaform | List all pharmaceutical forms.
*Besamv2Api* | [**listSubstances**](docs/Besamv2Api.md#listsubstances) | **GET** /rest/v2/be_samv2/substance | List all substances.
*Besamv2Api* | [**listVmpGroupsByVmpGroupCodes**](docs/Besamv2Api.md#listvmpgroupsbyvmpgroupcodes) | **POST** /rest/v2/be_samv2/vmpgroup/byGroupCodes | Finding AMPs by group.
*Besamv2Api* | [**listVmpsByGroupIds**](docs/Besamv2Api.md#listvmpsbygroupids) | **POST** /rest/v2/be_samv2/vmp/byGroupIds | Finding VMPs by group.
*Besamv2Api* | [**listVmpsByVmpCodes**](docs/Besamv2Api.md#listvmpsbyvmpcodes) | **POST** /rest/v2/be_samv2/vmp/byVmpCodes | Finding VMPs by group.
*CalendarItemApi* | [**createCalendarItem**](docs/CalendarItemApi.md#createcalendaritem) | **POST** /rest/v2/calendarItem | Creates a calendarItem
*CalendarItemApi* | [**deleteCalendarItem**](docs/CalendarItemApi.md#deletecalendaritem) | **POST** /rest/v2/calendarItem/{calendarItemIds} | Deletes an calendarItem
*CalendarItemApi* | [**deleteCalendarItems**](docs/CalendarItemApi.md#deletecalendaritems) | **POST** /rest/v2/calendarItem/delete/batch | Deletes calendarItems
*CalendarItemApi* | [**findCalendarItemsByHCPartyPatientForeignKeys**](docs/CalendarItemApi.md#findcalendaritemsbyhcpartypatientforeignkeys) | **GET** /rest/v2/calendarItem/byHcPartySecretForeignKeys | Find CalendarItems by hcparty and patient
*CalendarItemApi* | [**findCalendarItemsByRecurrenceId**](docs/CalendarItemApi.md#findcalendaritemsbyrecurrenceid) | **GET** /rest/v2/calendarItem/byRecurrenceId | Find CalendarItems by recurrenceId
*CalendarItemApi* | [**getCalendarItem**](docs/CalendarItemApi.md#getcalendaritem) | **GET** /rest/v2/calendarItem/{calendarItemId} | Gets an calendarItem
*CalendarItemApi* | [**getCalendarItems**](docs/CalendarItemApi.md#getcalendaritems) | **GET** /rest/v2/calendarItem | Gets all calendarItems
*CalendarItemApi* | [**getCalendarItemsByPeriodAndHcPartyId**](docs/CalendarItemApi.md#getcalendaritemsbyperiodandhcpartyid) | **POST** /rest/v2/calendarItem/byPeriodAndHcPartyId | Get CalendarItems by Period and HcPartyId
*CalendarItemApi* | [**getCalendarItemsWithIds**](docs/CalendarItemApi.md#getcalendaritemswithids) | **POST** /rest/v2/calendarItem/byIds | Get calendarItems by ids
*CalendarItemApi* | [**getCalendarsByPeriodAndAgendaId**](docs/CalendarItemApi.md#getcalendarsbyperiodandagendaid) | **POST** /rest/v2/calendarItem/byPeriodAndAgendaId | Get CalendarItems by Period and AgendaId
*CalendarItemApi* | [**modifyCalendarItem**](docs/CalendarItemApi.md#modifycalendaritem) | **PUT** /rest/v2/calendarItem | Modifies an calendarItem
*CalendarItemApi* | [**setCalendarItemsDelegations**](docs/CalendarItemApi.md#setcalendaritemsdelegations) | **POST** /rest/v2/calendarItem/delegations | Update delegations in calendarItems
*CalendarItemTypeApi* | [**createCalendarItemType**](docs/CalendarItemTypeApi.md#createcalendaritemtype) | **POST** /rest/v2/calendarItemType | Creates a calendarItemType
*CalendarItemTypeApi* | [**deleteCalendarItemTypes**](docs/CalendarItemTypeApi.md#deletecalendaritemtypes) | **POST** /rest/v2/calendarItemType/delete/batch | Deletes calendarItemTypes
*CalendarItemTypeApi* | [**getCalendarItemType**](docs/CalendarItemTypeApi.md#getcalendaritemtype) | **GET** /rest/v2/calendarItemType/{calendarItemTypeId} | Gets a calendarItemType
*CalendarItemTypeApi* | [**getCalendarItemTypes**](docs/CalendarItemTypeApi.md#getcalendaritemtypes) | **GET** /rest/v2/calendarItemType | Gets all calendarItemTypes
*CalendarItemTypeApi* | [**getCalendarItemTypesIncludeDeleted**](docs/CalendarItemTypeApi.md#getcalendaritemtypesincludedeleted) | **GET** /rest/v2/calendarItemType/includeDeleted | Gets all calendarItemTypes include deleted
*CalendarItemTypeApi* | [**modifyCalendarItemType**](docs/CalendarItemTypeApi.md#modifycalendaritemtype) | **PUT** /rest/v2/calendarItemType | Modifies an calendarItemType
*ClassificationApi* | [**createClassification**](docs/ClassificationApi.md#createclassification) | **POST** /rest/v2/classification | Create a classification with the current user
*ClassificationApi* | [**deleteClassifications**](docs/ClassificationApi.md#deleteclassifications) | **POST** /rest/v2/classification/delete/batch | Delete classification Templates.
*ClassificationApi* | [**findClassificationsByHCPartyPatientForeignKeys**](docs/ClassificationApi.md#findclassificationsbyhcpartypatientforeignkeys) | **GET** /rest/v2/classification/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
*ClassificationApi* | [**getClassification**](docs/ClassificationApi.md#getclassification) | **GET** /rest/v2/classification/{classificationId} | Get a classification Template
*ClassificationApi* | [**getClassificationByHcPartyId**](docs/ClassificationApi.md#getclassificationbyhcpartyid) | **GET** /rest/v2/classification/byIds/{ids} | Get a list of classifications
*ClassificationApi* | [**modifyClassification**](docs/ClassificationApi.md#modifyclassification) | **PUT** /rest/v2/classification | Modify a classification Template
*ClassificationApi* | [**newClassificationDelegations**](docs/ClassificationApi.md#newclassificationdelegations) | **POST** /rest/v2/classification/{classificationId}/delegate | Delegates a classification to a healthcare party
*ClassificationApi* | [**setClassificationsDelegations**](docs/ClassificationApi.md#setclassificationsdelegations) | **POST** /rest/v2/classification/delegations | Update delegations in classification
*ClassificationTemplateApi* | [**createClassificationTemplate**](docs/ClassificationTemplateApi.md#createclassificationtemplate) | **POST** /rest/v2/classificationTemplate | Create a classification Template with the current user
*ClassificationTemplateApi* | [**deleteClassificationTemplates**](docs/ClassificationTemplateApi.md#deleteclassificationtemplates) | **POST** /rest/v2/classificationTemplate/delete/batch | Delete classification Templates.
*ClassificationTemplateApi* | [**findClassificationTemplatesBy**](docs/ClassificationTemplateApi.md#findclassificationtemplatesby) | **GET** /rest/v2/classificationTemplate | List all classification templates with pagination
*ClassificationTemplateApi* | [**getClassificationTemplate**](docs/ClassificationTemplateApi.md#getclassificationtemplate) | **GET** /rest/v2/classificationTemplate/{classificationTemplateId} | Get a classification Template
*ClassificationTemplateApi* | [**getClassificationTemplateByIds**](docs/ClassificationTemplateApi.md#getclassificationtemplatebyids) | **GET** /rest/v2/classificationTemplate/byIds/{ids} | Get a list of classifications Templates
*ClassificationTemplateApi* | [**listClassificationTemplatesByHCPartyPatientForeignKeys**](docs/ClassificationTemplateApi.md#listclassificationtemplatesbyhcpartypatientforeignkeys) | **GET** /rest/v2/classificationTemplate/byHcPartySecretForeignKeys | List classification Templates found By Healthcare Party and secret foreign keyelementIds.
*ClassificationTemplateApi* | [**modifyClassificationTemplate**](docs/ClassificationTemplateApi.md#modifyclassificationtemplate) | **PUT** /rest/v2/classificationTemplate | Modify a classification Template
*ClassificationTemplateApi* | [**newClassificationTemplateDelegations**](docs/ClassificationTemplateApi.md#newclassificationtemplatedelegations) | **POST** /rest/v2/classificationTemplate/{classificationTemplateId}/delegate | Delegates a classification Template to a healthcare party
*CodeApi* | [**createCode**](docs/CodeApi.md#createcode) | **POST** /rest/v2/code | Create a Code
*CodeApi* | [**filterCodesBy**](docs/CodeApi.md#filtercodesby) | **POST** /rest/v2/code/filter | Filter codes 
*CodeApi* | [**findCodesByLabel**](docs/CodeApi.md#findcodesbylabel) | **GET** /rest/v2/code/byLabel | Finding codes by code, type and version with pagination.
*CodeApi* | [**findCodesByLink**](docs/CodeApi.md#findcodesbylink) | **GET** /rest/v2/code/byLink/{linkType} | Finding codes by code, type and version with pagination.
*CodeApi* | [**findCodesByType**](docs/CodeApi.md#findcodesbytype) | **GET** /rest/v2/code | Finding codes by code, type and version with pagination.
*CodeApi* | [**getCode**](docs/CodeApi.md#getcode) | **GET** /rest/v2/code/{codeId} | Get a code
*CodeApi* | [**getCodeWithParts**](docs/CodeApi.md#getcodewithparts) | **GET** /rest/v2/code/{type}/{code}/{version} | Get a code
*CodeApi* | [**getCodes**](docs/CodeApi.md#getcodes) | **POST** /rest/v2/code/byIds | Get a list of codes by ids
*CodeApi* | [**importCodes**](docs/CodeApi.md#importcodes) | **POST** /rest/v2/code/{codeType} | Import codes
*CodeApi* | [**listCodeTypesBy**](docs/CodeApi.md#listcodetypesby) | **GET** /rest/v2/code/codetype/byRegionType | Finding code types.
*CodeApi* | [**listCodesByRegionTypeCodeVersion**](docs/CodeApi.md#listcodesbyregiontypecodeversion) | **GET** /rest/v2/code/byRegionTypeCode | Finding codes by code, type and version
*CodeApi* | [**listTagTypesBy**](docs/CodeApi.md#listtagtypesby) | **GET** /rest/v2/code/tagtype/byRegionType | Finding tag types.
*CodeApi* | [**matchCodesBy**](docs/CodeApi.md#matchcodesby) | **POST** /rest/v2/code/match | Get ids of code matching the provided filter for the current user (HcParty) 
*CodeApi* | [**modifyCode**](docs/CodeApi.md#modifycode) | **PUT** /rest/v2/code | Modify a code
*ContactApi* | [**closeForHCPartyPatientForeignKeys**](docs/ContactApi.md#closeforhcpartypatientforeignkeys) | **PUT** /rest/v2/contact/byHcPartySecretForeignKeys/close | Close contacts for Healthcare Party and secret foreign keys.
*ContactApi* | [**createContact**](docs/ContactApi.md#createcontact) | **POST** /rest/v2/contact | Create a contact with the current user
*ContactApi* | [**createContacts**](docs/ContactApi.md#createcontacts) | **POST** /rest/v2/contact/batch | Create a batch of contacts
*ContactApi* | [**deleteContacts**](docs/ContactApi.md#deletecontacts) | **POST** /rest/v2/contact/delete/batch | Delete contacts.
*ContactApi* | [**filterContactsBy**](docs/ContactApi.md#filtercontactsby) | **POST** /rest/v2/contact/filter | List contacts for the current user (HcParty) or the given hcparty in the filter 
*ContactApi* | [**filterServicesBy**](docs/ContactApi.md#filterservicesby) | **POST** /rest/v2/contact/service/filter | List services for the current user (HcParty) or the given hcparty in the filter 
*ContactApi* | [**findContactsByOpeningDate**](docs/ContactApi.md#findcontactsbyopeningdate) | **GET** /rest/v2/contact/byOpeningDate | List contacts by opening date parties with(out) pagination
*ContactApi* | [**getContact**](docs/ContactApi.md#getcontact) | **GET** /rest/v2/contact/{contactId} | Get a contact
*ContactApi* | [**getContacts**](docs/ContactApi.md#getcontacts) | **POST** /rest/v2/contact/byIds | Get contacts
*ContactApi* | [**getEmptyContent**](docs/ContactApi.md#getemptycontent) | **GET** /rest/v2/contact/service/content/empty | Get an empty content
*ContactApi* | [**getServiceCodesOccurences**](docs/ContactApi.md#getservicecodesoccurences) | **GET** /rest/v2/contact/service/codes/{codeType}/{minOccurences} | Get the list of all used codes frequencies in services
*ContactApi* | [**getServices**](docs/ContactApi.md#getservices) | **POST** /rest/v2/contact/service | List services with provided ids 
*ContactApi* | [**getServicesLinkedTo**](docs/ContactApi.md#getserviceslinkedto) | **POST** /rest/v2/contact/service/linkedTo | List services linked to provided ids 
*ContactApi* | [**listContactByHCPartyServiceId**](docs/ContactApi.md#listcontactbyhcpartyserviceid) | **GET** /rest/v2/contact/byHcPartyServiceId | List contacts found By Healthcare Party and service Id.
*ContactApi* | [**listContactsByExternalId**](docs/ContactApi.md#listcontactsbyexternalid) | **POST** /rest/v2/contact/byExternalId | List contacts found By externalId.
*ContactApi* | [**listContactsByHCPartyAndFormId**](docs/ContactApi.md#listcontactsbyhcpartyandformid) | **GET** /rest/v2/contact/byHcPartyFormId | List contacts found By Healthcare Party and form Id.
*ContactApi* | [**listContactsByHCPartyAndFormIds**](docs/ContactApi.md#listcontactsbyhcpartyandformids) | **POST** /rest/v2/contact/byHcPartyFormIds | List contacts found By Healthcare Party and form Id.
*ContactApi* | [**listContactsByHCPartyAndPatientForeignKeys**](docs/ContactApi.md#listcontactsbyhcpartyandpatientforeignkeys) | **POST** /rest/v2/contact/byHcPartyPatientForeignKeys | List contacts found By Healthcare Party and Patient foreign keys.
*ContactApi* | [**listContactsByHCPartyAndPatientSecretFKeys**](docs/ContactApi.md#listcontactsbyhcpartyandpatientsecretfkeys) | **GET** /rest/v2/contact/byHcPartySecretForeignKeys | List contacts found By Healthcare Party and secret foreign keys.
*ContactApi* | [**listContactsDelegationsStubsByHCPartyAndPatientForeignKeys**](docs/ContactApi.md#listcontactsdelegationsstubsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/contact/byHcPartySecretForeignKeys/delegations | List contacts found By Healthcare Party and secret foreign keys.
*ContactApi* | [**listServicesByAssociationId**](docs/ContactApi.md#listservicesbyassociationid) | **GET** /rest/v2/contact/service/associationId | List services by related association id
*ContactApi* | [**listServicesByHealthElementId**](docs/ContactApi.md#listservicesbyhealthelementid) | **GET** /rest/v2/contact/service/healthElementId/{healthElementId} | List services linked to a health element
*ContactApi* | [**matchContactsBy**](docs/ContactApi.md#matchcontactsby) | **POST** /rest/v2/contact/match | Get ids of contacts matching the provided filter for the current user (HcParty) 
*ContactApi* | [**matchServicesBy**](docs/ContactApi.md#matchservicesby) | **POST** /rest/v2/contact/service/match | Get ids of services matching the provided filter for the current user
*ContactApi* | [**modifyContact**](docs/ContactApi.md#modifycontact) | **PUT** /rest/v2/contact | Modify a contact
*ContactApi* | [**modifyContacts**](docs/ContactApi.md#modifycontacts) | **PUT** /rest/v2/contact/batch | Modify a batch of contacts
*ContactApi* | [**modifyContactsDelegations**](docs/ContactApi.md#modifycontactsdelegations) | **PUT** /rest/v2/contact/delegations | Update delegations in healthElements.
*ContactApi* | [**newContactDelegations**](docs/ContactApi.md#newcontactdelegations) | **POST** /rest/v2/contact/{contactId}/delegate | Delegates a contact to a healthcare party
*ContactApi* | [**setContactsDelegations**](docs/ContactApi.md#setcontactsdelegations) | **POST** /rest/v2/contact/delegations | Update delegations in healthElements.
*DeviceApi* | [**createDevice**](docs/DeviceApi.md#createdevice) | **POST** /rest/v2/device | Create a device
*DeviceApi* | [**createDeviceInGroup**](docs/DeviceApi.md#createdeviceingroup) | **POST** /rest/v2/device/inGroup/{groupId} | Create a device
*DeviceApi* | [**createDevices**](docs/DeviceApi.md#createdevices) | **POST** /rest/v2/device/batch | Create devices in bulk
*DeviceApi* | [**createDevices1**](docs/DeviceApi.md#createdevices1) | **POST** /rest/v2/device/bulk | Create devices in bulk
*DeviceApi* | [**deleteDevice**](docs/DeviceApi.md#deletedevice) | **DELETE** /rest/v2/device/{deviceId} | Delete device.
*DeviceApi* | [**deleteDevices**](docs/DeviceApi.md#deletedevices) | **POST** /rest/v2/device/delete/batch | Delete devices.
*DeviceApi* | [**deleteDevicesInGroup**](docs/DeviceApi.md#deletedevicesingroup) | **DELETE** /rest/v2/device/inGroup/{groupId}/{deviceIds} | Delete a device
*DeviceApi* | [**filterDevicesBy**](docs/DeviceApi.md#filterdevicesby) | **POST** /rest/v2/device/filter | Filter devices for the current user (HcParty) 
*DeviceApi* | [**getDevice**](docs/DeviceApi.md#getdevice) | **GET** /rest/v2/device/{deviceId} | Get Device
*DeviceApi* | [**getDeviceHcPartyKeysForDelegate**](docs/DeviceApi.md#getdevicehcpartykeysfordelegate) | **GET** /rest/v2/device/{deviceId}/keys | Get the HcParty encrypted AES keys indexed by owner
*DeviceApi* | [**getDeviceAesExchangeKeysForDelegate**](docs/DeviceApi.md#getdeviceaesexchangekeysfordelegate) | **GET** /rest/v2/device/{deviceId}/aesExchangeKeys | Get the HcParty encrypted AES keys indexed by owner.
*DeviceApi* | [**getDevices**](docs/DeviceApi.md#getdevices) | **POST** /rest/v2/device/byIds | Get devices by id
*DeviceApi* | [**getDevicesInGroup**](docs/DeviceApi.md#getdevicesingroup) | **POST** /rest/v2/device/inGroup/{groupId}/byIds | Get devices by their IDs
*DeviceApi* | [**matchDevicesBy**](docs/DeviceApi.md#matchdevicesby) | **POST** /rest/v2/device/match | Get ids of devices matching the provided filter for the current user (HcParty) 
*DeviceApi* | [**modifyDeviceInGroup**](docs/DeviceApi.md#modifydeviceingroup) | **PUT** /rest/v2/device/inGroup/{groupId} | Modify a Device.
*DeviceApi* | [**updateDevice**](docs/DeviceApi.md#updatedevice) | **PUT** /rest/v2/device | Modify a device
*DeviceApi* | [**updateDevices**](docs/DeviceApi.md#updatedevices) | **PUT** /rest/v2/device/batch | Modify devices in bulk
*DeviceApi* | [**updateDevices1**](docs/DeviceApi.md#updatedevices1) | **PUT** /rest/v2/device/bulk | Modify devices in bulk
*DocumentApi* | [**createDocument**](docs/DocumentApi.md#createdocument) | **POST** /rest/v2/document | Creates a document
*DocumentApi* | [**deleteAttachment**](docs/DocumentApi.md#deleteattachment) | **DELETE** /rest/v2/document/{documentId}/attachment | Deletes a document's attachment
*DocumentApi* | [**deleteDocument**](docs/DocumentApi.md#deletedocument) | **POST** /rest/v2/document/delete/batch | Deletes documents
*DocumentApi* | [**findWithoutDelegation**](docs/DocumentApi.md#findwithoutdelegation) | **GET** /rest/v2/document/woDelegation | List documents with no delegation
*DocumentApi* | [**getDocument**](docs/DocumentApi.md#getdocument) | **GET** /rest/v2/document/{documentId} | Gets a document
*DocumentApi* | [**getDocumentAttachment**](docs/DocumentApi.md#getdocumentattachment) | **GET** /rest/v2/document/{documentId}/attachment/{attachmentId} | Load document's attachment
*DocumentApi* | [**getDocumentByExternalUuid**](docs/DocumentApi.md#getdocumentbyexternaluuid) | **GET** /rest/v2/document/externaluuid/{externalUuid} | Gets a document
*DocumentApi* | [**getDocuments**](docs/DocumentApi.md#getdocuments) | **POST** /rest/v2/document/byIds | Gets a document
*DocumentApi* | [**getDocumentsByExternalUuid**](docs/DocumentApi.md#getdocumentsbyexternaluuid) | **GET** /rest/v2/document/externaluuid/{externalUuid}/all | Get all documents with externalUuid
*DocumentApi* | [**listDocumentByTypeHCPartyMessageSecretFKeys**](docs/DocumentApi.md#listdocumentbytypehcpartymessagesecretfkeys) | **GET** /rest/v2/document/byTypeHcPartySecretForeignKeys | List documents found By type, By Healthcare Party and secret foreign keys.
*DocumentApi* | [**listDocumentsByHCPartyAndPatientForeignKeys**](docs/DocumentApi.md#listdocumentsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/document/byHcPartySecretForeignKeys | List documents found By Healthcare Party and secret foreign keys.
*DocumentApi* | [**modifyDocument**](docs/DocumentApi.md#modifydocument) | **PUT** /rest/v2/document | Updates a document
*DocumentApi* | [**modifyDocuments**](docs/DocumentApi.md#modifydocuments) | **PUT** /rest/v2/document/batch | Updates a batch of documents
*DocumentApi* | [**setDocumentAttachment**](docs/DocumentApi.md#setdocumentattachment) | **PUT** /rest/v2/document/{documentId}/attachment | Creates a document's attachment
*DocumentApi* | [**setDocumentAttachmentMulti**](docs/DocumentApi.md#setdocumentattachmentmulti) | **PUT** /rest/v2/document/{documentId}/attachment/multipart | Creates a document's attachment
*DocumentApi* | [**setDocumentsDelegations**](docs/DocumentApi.md#setdocumentsdelegations) | **POST** /rest/v2/document/delegations | Update delegations in healthElements.
*DocumentApi* | [**setSafeDocumentAttachment**](docs/DocumentApi.md#setsafedocumentattachment) | **PUT** /rest/v2/document/attachment | Creates a document's attachment
*DocumentTemplateApi* | [**createDocumentTemplate**](docs/DocumentTemplateApi.md#createdocumenttemplate) | **POST** /rest/v2/doctemplate | Create a document template with the current user
*DocumentTemplateApi* | [**deleteDocumentTemplates**](docs/DocumentTemplateApi.md#deletedocumenttemplates) | **POST** /rest/v2/doctemplate/delete/batch | Deletes document templates
*DocumentTemplateApi* | [**getAttachmentText**](docs/DocumentTemplateApi.md#getattachmenttext) | **GET** /rest/v2/doctemplate/{documentTemplateId}/attachmentText/{attachmentId} | Download a the document template attachment
*DocumentTemplateApi* | [**getDocumentTemplate**](docs/DocumentTemplateApi.md#getdocumenttemplate) | **GET** /rest/v2/doctemplate/{documentTemplateId} | Gets a document template
*DocumentTemplateApi* | [**getDocumentTemplateAttachment**](docs/DocumentTemplateApi.md#getdocumenttemplateattachment) | **GET** /rest/v2/doctemplate/{documentTemplateId}/attachment/{attachmentId} | Download a the document template attachment
*DocumentTemplateApi* | [**listAllDocumentTemplates**](docs/DocumentTemplateApi.md#listalldocumenttemplates) | **GET** /rest/v2/doctemplate/find/all | Gets all document templates for all users
*DocumentTemplateApi* | [**listDocumentTemplates**](docs/DocumentTemplateApi.md#listdocumenttemplates) | **GET** /rest/v2/doctemplate | Gets all document templates for current user
*DocumentTemplateApi* | [**listDocumentTemplatesByDocumentType**](docs/DocumentTemplateApi.md#listdocumenttemplatesbydocumenttype) | **GET** /rest/v2/doctemplate/byDocumentType/{documentTypeCode} | Gets all document templates by Type
*DocumentTemplateApi* | [**listDocumentTemplatesByDocumentTypeForCurrentUser**](docs/DocumentTemplateApi.md#listdocumenttemplatesbydocumenttypeforcurrentuser) | **GET** /rest/v2/doctemplate/byDocumentTypeForCurrentUser/{documentTypeCode} | Gets all document templates by Type For currentUser
*DocumentTemplateApi* | [**listDocumentTemplatesBySpeciality**](docs/DocumentTemplateApi.md#listdocumenttemplatesbyspeciality) | **GET** /rest/v2/doctemplate/bySpecialty/{specialityCode} | Gets all document templates
*DocumentTemplateApi* | [**modifyDocumentTemplate**](docs/DocumentTemplateApi.md#modifydocumenttemplate) | **PUT** /rest/v2/doctemplate/{documentTemplateId} | Modify a document template with the current user
*DocumentTemplateApi* | [**setDocumentTemplateAttachment**](docs/DocumentTemplateApi.md#setdocumenttemplateattachment) | **PUT** /rest/v2/doctemplate/{documentTemplateId}/attachment | Creates a document's attachment
*DocumentTemplateApi* | [**setDocumentTemplateAttachmentJson**](docs/DocumentTemplateApi.md#setdocumenttemplateattachmentjson) | **PUT** /rest/v2/doctemplate/{documentTemplateId}/attachmentJson | Creates a document's attachment
*EntityTemplateApi* | [**createEntityTemplate**](docs/EntityTemplateApi.md#createentitytemplate) | **POST** /rest/v2/entitytemplate | Create a EntityTemplate
*EntityTemplateApi* | [**createEntityTemplates**](docs/EntityTemplateApi.md#createentitytemplates) | **POST** /rest/v2/entitytemplate/batch | Create a batch of entityTemplates
*EntityTemplateApi* | [**deleteEntityTemplate**](docs/EntityTemplateApi.md#deleteentitytemplate) | **POST** /rest/v2/entitytemplate/delete/batch | Delete entity templates
*EntityTemplateApi* | [**findAllEntityTemplatesByKeyword**](docs/EntityTemplateApi.md#findallentitytemplatesbykeyword) | **GET** /rest/v2/entitytemplate/findAll/{type}/keyword/{keyword} | Finding entityTemplates by entityTemplate, type and version with pagination.
*EntityTemplateApi* | [**getEntityTemplate**](docs/EntityTemplateApi.md#getentitytemplate) | **GET** /rest/v2/entitytemplate/{entityTemplateId} | Get a entityTemplate
*EntityTemplateApi* | [**getEntityTemplates**](docs/EntityTemplateApi.md#getentitytemplates) | **POST** /rest/v2/entitytemplate/byIds | Get a list of entityTemplates by ids
*EntityTemplateApi* | [**listAllEntityTemplatesBy**](docs/EntityTemplateApi.md#listallentitytemplatesby) | **GET** /rest/v2/entitytemplate/findAll/{type} | Finding entityTemplates by entityTemplate, type and version with pagination.
*EntityTemplateApi* | [**listEntityTemplatesBy**](docs/EntityTemplateApi.md#listentitytemplatesby) | **GET** /rest/v2/entitytemplate/find/{userId}/{type} | Finding entityTemplates by userId, entityTemplate, type and version with pagination.
*EntityTemplateApi* | [**listEntityTemplatesByKeyword**](docs/EntityTemplateApi.md#listentitytemplatesbykeyword) | **GET** /rest/v2/entitytemplate/find/{userId}/{type}/keyword/{keyword} | Finding entityTemplates by userId, type and keyword.
*EntityTemplateApi* | [**modifyEntityTemplate**](docs/EntityTemplateApi.md#modifyentitytemplate) | **PUT** /rest/v2/entitytemplate | Modify a entityTemplate
*EntityTemplateApi* | [**modifyEntityTemplates**](docs/EntityTemplateApi.md#modifyentitytemplates) | **PUT** /rest/v2/entitytemplate/batch | Modify a batch of entityTemplates
*EntityrefApi* | [**createEntityReference**](docs/EntityrefApi.md#createentityreference) | **POST** /rest/v2/entityref | Create an entity reference
*EntityrefApi* | [**getLatest**](docs/EntityrefApi.md#getlatest) | **GET** /rest/v2/entityref/latest/{prefix} | Find latest reference for a prefix 
*FormApi* | [**createForm**](docs/FormApi.md#createform) | **POST** /rest/v2/form | Create a form with the current user
*FormApi* | [**createFormTemplate**](docs/FormApi.md#createformtemplate) | **POST** /rest/v2/form/template | Create a form template with the current user
*FormApi* | [**createForms**](docs/FormApi.md#createforms) | **POST** /rest/v2/form/batch | Create a batch of forms
*FormApi* | [**deleteFormTemplate**](docs/FormApi.md#deleteformtemplate) | **DELETE** /rest/v2/form/template/{formTemplateId} | Delete a form template
*FormApi* | [**deleteForms**](docs/FormApi.md#deleteforms) | **POST** /rest/v2/form/delete/batch | Delete forms.
*FormApi* | [**getChildrenForms**](docs/FormApi.md#getchildrenforms) | **GET** /rest/v2/form/childrenOf/{formId}/{hcPartyId} | Get a list of forms by parents ids
*FormApi* | [**getForm**](docs/FormApi.md#getform) | **GET** /rest/v2/form/{formId} | Gets a form
*FormApi* | [**getFormByLogicalUuid**](docs/FormApi.md#getformbylogicaluuid) | **GET** /rest/v2/form/logicalUuid/{logicalUuid} | Gets the most recent form with the given logicalUuid
*FormApi* | [**getFormByUniqueId**](docs/FormApi.md#getformbyuniqueid) | **GET** /rest/v2/form/uniqueId/{uniqueId} | Gets the most recent form with the given uniqueId
*FormApi* | [**getFormTemplate**](docs/FormApi.md#getformtemplate) | **GET** /rest/v2/form/template/{formTemplateId} | Gets a form template by guid
*FormApi* | [**getFormTemplates**](docs/FormApi.md#getformtemplates) | **GET** /rest/v2/form/template | Gets all form templates for current user
*FormApi* | [**getFormTemplatesByGuid**](docs/FormApi.md#getformtemplatesbyguid) | **GET** /rest/v2/form/template/{specialityCode}/guid/{formTemplateGuid} | Gets a form template
*FormApi* | [**getForms**](docs/FormApi.md#getforms) | **POST** /rest/v2/form/byIds | Get a list of forms by ids
*FormApi* | [**getFormsByLogicalUuid**](docs/FormApi.md#getformsbylogicaluuid) | **GET** /rest/v2/form/all/logicalUuid/{logicalUuid} | Gets all forms with given logicalUuid
*FormApi* | [**getFormsByUniqueId**](docs/FormApi.md#getformsbyuniqueid) | **GET** /rest/v2/form/all/uniqueId/{uniqueId} | Gets all forms by uniqueId
*FormApi* | [**listFormTemplatesBySpeciality**](docs/FormApi.md#listformtemplatesbyspeciality) | **GET** /rest/v2/form/template/bySpecialty/{specialityCode} | Gets all form templates
*FormApi* | [**listFormsByHCPartyAndPatientForeignKeys**](docs/FormApi.md#listformsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/form/byHcPartySecretForeignKeys | List forms found By Healthcare Party and secret foreign keys.
*FormApi* | [**listFormsDelegationsStubsByHCPartyAndPatientForeignKeys**](docs/FormApi.md#listformsdelegationsstubsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/form/byHcPartySecretForeignKeys/delegations | List form stubs found By Healthcare Party and secret foreign keys.
*FormApi* | [**modifyForm**](docs/FormApi.md#modifyform) | **PUT** /rest/v2/form | Modify a form
*FormApi* | [**modifyForms**](docs/FormApi.md#modifyforms) | **PUT** /rest/v2/form/batch | Modify a batch of forms
*FormApi* | [**newFormDelegations**](docs/FormApi.md#newformdelegations) | **POST** /rest/v2/form/delegate/{formId} | Delegates a form to a healthcare party
*FormApi* | [**setFormsDelegations**](docs/FormApi.md#setformsdelegations) | **POST** /rest/v2/form/delegations | Update delegations in form.
*FormApi* | [**setTemplateAttachmentMulti**](docs/FormApi.md#settemplateattachmentmulti) | **PUT** /rest/v2/form/template/{formTemplateId}/attachment/multipart | Update a form template's layout
*FormApi* | [**updateFormTemplate**](docs/FormApi.md#updateformtemplate) | **PUT** /rest/v2/form/template/{formTemplateId} | Modify a form template with the current user
*FrontEndMigrationApi* | [**createFrontEndMigration**](docs/FrontEndMigrationApi.md#createfrontendmigration) | **POST** /rest/v2/frontendmigration | Creates a front end migration
*FrontEndMigrationApi* | [**deleteFrontEndMigration**](docs/FrontEndMigrationApi.md#deletefrontendmigration) | **DELETE** /rest/v2/frontendmigration/{frontEndMigrationId} | Deletes a front end migration
*FrontEndMigrationApi* | [**getFrontEndMigration**](docs/FrontEndMigrationApi.md#getfrontendmigration) | **GET** /rest/v2/frontendmigration/{frontEndMigrationId} | Gets a front end migration
*FrontEndMigrationApi* | [**getFrontEndMigrationByName**](docs/FrontEndMigrationApi.md#getfrontendmigrationbyname) | **GET** /rest/v2/frontendmigration/byName/{frontEndMigrationName} | Gets an front end migration
*FrontEndMigrationApi* | [**getFrontEndMigrations**](docs/FrontEndMigrationApi.md#getfrontendmigrations) | **GET** /rest/v2/frontendmigration | Gets a front end migration
*FrontEndMigrationApi* | [**modifyFrontEndMigration**](docs/FrontEndMigrationApi.md#modifyfrontendmigration) | **PUT** /rest/v2/frontendmigration | Modifies a front end migration
*GroupApi* | [**createGroup**](docs/GroupApi.md#creategroup) | **POST** /rest/v2/group/{id} | Create a group
*GroupApi* | [**deleteGroup**](docs/GroupApi.md#deletegroup) | **DELETE** /rest/v2/group/{id} | Delete group
*GroupApi* | [**findGroups**](docs/GroupApi.md#findgroups) | **GET** /rest/v2/group/{id}/children | Find groups by parent
*GroupApi* | [**findGroupsWithContent**](docs/GroupApi.md#findgroupswithcontent) | **GET** /rest/v2/group/{id}/children/search | Find groups by parent and content
*GroupApi* | [**getGroup**](docs/GroupApi.md#getgroup) | **GET** /rest/v2/group/{id} | Get a group by id
*GroupApi* | [**getGroupsStorageInfos**](docs/GroupApi.md#getgroupsstorageinfos) | **POST** /rest/v2/group/storage/info | Reset storage for group
*GroupApi* | [**getReplicationInfo1**](docs/GroupApi.md#getreplicationinfo1) | **GET** /rest/v2/group/{id}/r | Get index info
*GroupApi* | [**initDesignDocs**](docs/GroupApi.md#initdesigndocs) | **PUT** /rest/v2/group/{id}/dd | Init design docs
*GroupApi* | [**listApps**](docs/GroupApi.md#listapps) | **GET** /rest/v2/group/apps | List apps
*GroupApi* | [**listGroups**](docs/GroupApi.md#listgroups) | **GET** /rest/v2/group | List groups
*GroupApi* | [**modifyGroupName**](docs/GroupApi.md#modifygroupname) | **PUT** /rest/v2/group/{id}/name/{name} | Update group name
*GroupApi* | [**modifyGroupProperties**](docs/GroupApi.md#modifygroupproperties) | **PUT** /rest/v2/group/{id}/properties | Update group properties
*GroupApi* | [**registerNewGroupAdministrator**](docs/GroupApi.md#registernewgroupadministrator) | **POST** /rest/v2/group/register/trial | Create a group
*GroupApi* | [**resetStorage**](docs/GroupApi.md#resetstorage) | **POST** /rest/v2/group/{id}/reset/storage | Reset storage for group
*GroupApi* | [**setGroupPassword**](docs/GroupApi.md#setgrouppassword) | **PUT** /rest/v2/group/{id}/password | Set group password
*GroupApi* | [**solveConflicts**](docs/GroupApi.md#solveconflicts) | **POST** /rest/v2/group/{id}/conflicts | Solve conflicts for group
*HealthElementApi* | [**createHealthElement**](docs/HealthElementApi.md#createhealthelement) | **POST** /rest/v2/helement | Create a health element with the current user
*HealthElementApi* | [**createHealthElements**](docs/HealthElementApi.md#createhealthelements) | **POST** /rest/v2/helement/batch | Create a batch of healthcare elements
*HealthElementApi* | [**deleteHealthElements**](docs/HealthElementApi.md#deletehealthelements) | **POST** /rest/v2/helement/delete/batch | Delete health elements.
*HealthElementApi* | [**filterHealthElementsBy**](docs/HealthElementApi.md#filterhealthelementsby) | **POST** /rest/v2/helement/filter | Filter health elements for the current user (HcParty)
*HealthElementApi* | [**getHealthElement**](docs/HealthElementApi.md#gethealthelement) | **GET** /rest/v2/helement/{healthElementId} | Get a health element
*HealthElementApi* | [**getHealthElements**](docs/HealthElementApi.md#gethealthelements) | **POST** /rest/v2/helement/byIds | Get healthElements by batch
*HealthElementApi* | [**listHealthElementsByHCPartyAndPatientForeignKeys**](docs/HealthElementApi.md#listhealthelementsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/helement/byHcPartySecretForeignKeys | List health elements found By Healthcare Party and secret foreign keyelementIds.
*HealthElementApi* | [**listHealthElementsDelegationsStubsByHCPartyAndPatientForeignKeys**](docs/HealthElementApi.md#listhealthelementsdelegationsstubsbyhcpartyandpatientforeignkeys) | **GET** /rest/v2/helement/byHcPartySecretForeignKeys/delegations | List helement stubs found By Healthcare Party and secret foreign keys.
*HealthElementApi* | [**matchHealthElementsBy**](docs/HealthElementApi.md#matchhealthelementsby) | **POST** /rest/v2/helement/match | Get ids of health element matching the provided filter for the current user (HcParty) 
*HealthElementApi* | [**modifyHealthElement**](docs/HealthElementApi.md#modifyhealthelement) | **PUT** /rest/v2/helement | Modify a health element
*HealthElementApi* | [**modifyHealthElements**](docs/HealthElementApi.md#modifyhealthelements) | **PUT** /rest/v2/helement/batch | Modify a batch of health elements
*HealthElementApi* | [**newHealthElementDelegations**](docs/HealthElementApi.md#newhealthelementdelegations) | **POST** /rest/v2/helement/{healthElementId}/delegate | Delegates a health element to a healthcare party
*HealthElementApi* | [**setHealthElementsDelegations**](docs/HealthElementApi.md#sethealthelementsdelegations) | **POST** /rest/v2/helement/delegations | Update delegations in healthElements.
*HealthcarePartyApi* | [**createHealthcareParty**](docs/HealthcarePartyApi.md#createhealthcareparty) | **POST** /rest/v2/hcparty | Create a healthcare party
*HealthcarePartyApi* | [**createHealthcarePartyInGroup**](docs/HealthcarePartyApi.md#createhealthcarepartyingroup) | **POST** /rest/v2/hcparty/inGroup/{groupId} | Create a healthcare party
*HealthcarePartyApi* | [**deleteHealthcareParties**](docs/HealthcarePartyApi.md#deletehealthcareparties) | **POST** /rest/v2/hcparty/delete/batch | Delete healthcare parties
*HealthcarePartyApi* | [**deleteHealthcarePartiesInGroup**](docs/HealthcarePartyApi.md#deletehealthcarepartiesingroup) | **POST** /rest/v2/hcparty/delete/batch/inGroup/{groupId} | Delete a healthcare party
*HealthcarePartyApi* | [**filterHealthPartiesBy**](docs/HealthcarePartyApi.md#filterhealthpartiesby) | **POST** /rest/v2/hcparty/filter | Filter healthcare parties for the current user (HcParty)
*HealthcarePartyApi* | [**findHealthcarePartiesBy**](docs/HealthcarePartyApi.md#findhealthcarepartiesby) | **GET** /rest/v2/hcparty | List healthcare parties with(out) pagination
*HealthcarePartyApi* | [**findHealthcarePartiesByName**](docs/HealthcarePartyApi.md#findhealthcarepartiesbyname) | **GET** /rest/v2/hcparty/byName | Find healthcare parties by name with(out) pagination
*HealthcarePartyApi* | [**findHealthcarePartiesBySpecialityAndPostCode**](docs/HealthcarePartyApi.md#findhealthcarepartiesbyspecialityandpostcode) | **GET** /rest/v2/hcparty/bySpecialityAndPostCode/{type}/{spec}/{firstCode}/to/{lastCode} | Find healthcare parties by name with(out) pagination
*HealthcarePartyApi* | [**findHealthcarePartiesBySsinOrNihii**](docs/HealthcarePartyApi.md#findhealthcarepartiesbyssinornihii) | **GET** /rest/v2/hcparty/byNihiiOrSsin/{searchValue} | Find healthcare parties by nihii or ssin with(out) pagination
*HealthcarePartyApi* | [**getHcPartyKeysForDelegate**](docs/HealthcarePartyApi.md#gethcpartykeysfordelegate) | **GET** /rest/v2/hcparty/byKeys/{healthcarePartyId} | Get the HcParty encrypted AES keys indexed by owner
*HealthcarePartyApi* | [**getAesExchangeKeysForDelegate**](docs/HealthcarePartyApi.md#getaesexchangekeysfordelegate) | **GET** /rest/v2/hcparty/{healthcarePartyId}/aesExchangeKeys | Get the HcParty encrypted AES keys indexed by owner.
*HealthcarePartyApi* | [**getCurrentHealthcareParty**](docs/HealthcarePartyApi.md#getcurrenthealthcareparty) | **GET** /rest/v2/hcparty/current | Get the current healthcare party if logged in.
*HealthcarePartyApi* | [**getHealthcareParties**](docs/HealthcarePartyApi.md#gethealthcareparties) | **POST** /rest/v2/hcparty/byIds | Get healthcareParties by their IDs
*HealthcarePartyApi* | [**getHealthcareParty**](docs/HealthcarePartyApi.md#gethealthcareparty) | **GET** /rest/v2/hcparty/{healthcarePartyId} | Get a healthcareParty by his ID
*HealthcarePartyApi* | [**getPublicKey**](docs/HealthcarePartyApi.md#getpublickey) | **GET** /rest/v2/hcparty/{healthcarePartyId}/publicKey | Get public key of a healthcare party
*HealthcarePartyApi* | [**listHealthcarePartiesByName**](docs/HealthcarePartyApi.md#listhealthcarepartiesbyname) | **GET** /rest/v2/hcparty/byNameStrict/{name} | Find healthcare parties by name with(out) pagination
*HealthcarePartyApi* | [**listHealthcarePartiesByParentId**](docs/HealthcarePartyApi.md#listhealthcarepartiesbyparentid) | **GET** /rest/v2/hcparty/{parentId}/children | Find children of an healthcare parties
*HealthcarePartyApi* | [**matchHealthcarePartiesBy**](docs/HealthcarePartyApi.md#matchhealthcarepartiesby) | **POST** /rest/v2/hcparty/match | Get ids of healthcare party matching the provided filter for the current user (HcParty) 
*HealthcarePartyApi* | [**modifyHealthcareParty**](docs/HealthcarePartyApi.md#modifyhealthcareparty) | **PUT** /rest/v2/hcparty | Modify a Healthcare Party.
*HealthcarePartyApi* | [**modifyHealthcarePartyInGroup**](docs/HealthcarePartyApi.md#modifyhealthcarepartyingroup) | **PUT** /rest/v2/hcparty/inGroup/{groupId} | Modify a Healthcare Party.
*HealthcarePartyApi* | [**registerPatient1**](docs/HealthcarePartyApi.md#registerpatient1) | **POST** /rest/v2/hcparty/register/inGroup/{groupId} | Register a hcp
*IcureApi* | [**getIndexingInfo**](docs/IcureApi.md#getindexinginfo) | **GET** /rest/v2/icure/i | Get index info
*IcureApi* | [**getProcessInfo**](docs/IcureApi.md#getprocessinfo) | **GET** /rest/v2/icure/p | Get process info
*IcureApi* | [**getReplicationInfo**](docs/IcureApi.md#getreplicationinfo) | **GET** /rest/v2/icure/r | Get replication info
*IcureApi* | [**getReplicatorInfo**](docs/IcureApi.md#getreplicatorinfo) | **GET** /rest/v2/icure/r/{id} | Get replication info
*IcureApi* | [**getUserSyncInfo**](docs/IcureApi.md#getusersyncinfo) | **GET** /rest/v2/icure/sync/user | Get user sync info
*IcureApi* | [**getVersion**](docs/IcureApi.md#getversion) | **GET** /rest/v2/icure/v | Get version
*IcureApi* | [**isReady**](docs/IcureApi.md#isready) | **GET** /rest/v2/icure/ok | Check if a user exists
*IcureApi* | [**resolveContactsConflicts**](docs/IcureApi.md#resolvecontactsconflicts) | **POST** /rest/v2/icure/conflicts/contact | Resolve contacts conflicts
*IcureApi* | [**resolveDocumentsConflicts**](docs/IcureApi.md#resolvedocumentsconflicts) | **POST** /rest/v2/icure/conflicts/document | resolve documents conflicts
*IcureApi* | [**resolveFormsConflicts**](docs/IcureApi.md#resolveformsconflicts) | **POST** /rest/v2/icure/conflicts/form | resolve forms conflicts
*IcureApi* | [**resolveHealthElementsConflicts**](docs/IcureApi.md#resolvehealthelementsconflicts) | **POST** /rest/v2/icure/conflicts/healthelement | resolve healthcare elements conflicts
*IcureApi* | [**resolveInvoicesConflicts**](docs/IcureApi.md#resolveinvoicesconflicts) | **POST** /rest/v2/icure/conflicts/invoice | resolve invoices conflicts
*IcureApi* | [**resolveMessagesConflicts**](docs/IcureApi.md#resolvemessagesconflicts) | **POST** /rest/v2/icure/conflicts/message | resolve messages conflicts
*IcureApi* | [**resolvePatientsConflicts**](docs/IcureApi.md#resolvepatientsconflicts) | **POST** /rest/v2/icure/conflicts/patient | Resolve patients conflicts
*IcureApi* | [**updateDesignDoc**](docs/IcureApi.md#updatedesigndoc) | **POST** /rest/v2/icure/dd/{entityName} | Force update design doc
*InsuranceApi* | [**createInsurance**](docs/InsuranceApi.md#createinsurance) | **POST** /rest/v2/insurance | Creates an insurance
*InsuranceApi* | [**deleteInsurance**](docs/InsuranceApi.md#deleteinsurance) | **DELETE** /rest/v2/insurance/{insuranceId} | Deletes an insurance
*InsuranceApi* | [**getInsurance**](docs/InsuranceApi.md#getinsurance) | **GET** /rest/v2/insurance/{insuranceId} | Gets an insurance
*InsuranceApi* | [**getInsurances**](docs/InsuranceApi.md#getinsurances) | **POST** /rest/v2/insurance/byIds | Gets insurances by id
*InsuranceApi* | [**listInsurancesByCode**](docs/InsuranceApi.md#listinsurancesbycode) | **GET** /rest/v2/insurance/byCode/{insuranceCode} | Gets an insurance
*InsuranceApi* | [**listInsurancesByName**](docs/InsuranceApi.md#listinsurancesbyname) | **GET** /rest/v2/insurance/byName/{insuranceName} | Gets an insurance
*InsuranceApi* | [**modifyInsurance**](docs/InsuranceApi.md#modifyinsurance) | **PUT** /rest/v2/insurance | Modifies an insurance
*InvoiceApi* | [**appendCodes**](docs/InvoiceApi.md#appendcodes) | **POST** /rest/v2/invoice/byauthor/{userId}/append/{type}/{sentMediumType} | Gets all invoices for author at date
*InvoiceApi* | [**createInvoice**](docs/InvoiceApi.md#createinvoice) | **POST** /rest/v2/invoice | Creates an invoice
*InvoiceApi* | [**createInvoices**](docs/InvoiceApi.md#createinvoices) | **POST** /rest/v2/invoice/batch | Create a batch of invoices
*InvoiceApi* | [**deleteInvoice**](docs/InvoiceApi.md#deleteinvoice) | **DELETE** /rest/v2/invoice/{invoiceId} | Deletes an invoice
*InvoiceApi* | [**filterInvoicesBy**](docs/InvoiceApi.md#filterinvoicesby) | **POST** /rest/v2/invoice/filter | Filter invoices for the current user (HcParty)
*InvoiceApi* | [**findInvoicesByAuthor**](docs/InvoiceApi.md#findinvoicesbyauthor) | **GET** /rest/v2/invoice/byauthor/{hcPartyId} | Gets all invoices for author at date
*InvoiceApi* | [**getInvoice**](docs/InvoiceApi.md#getinvoice) | **GET** /rest/v2/invoice/{invoiceId} | Gets an invoice
*InvoiceApi* | [**getInvoices**](docs/InvoiceApi.md#getinvoices) | **POST** /rest/v2/invoice/byIds | Gets an invoice
*InvoiceApi* | [**getTarificationsCodesOccurences**](docs/InvoiceApi.md#gettarificationscodesoccurences) | **GET** /rest/v2/invoice/codes/{minOccurences} | Get the list of all used tarifications frequencies in invoices
*InvoiceApi* | [**listAllHcpsByStatus**](docs/InvoiceApi.md#listallhcpsbystatus) | **POST** /rest/v2/invoice/allHcpsByStatus/{status} | Gets all invoices per status
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
*InvoiceApi* | [**listToInsurancesUnsent**](docs/InvoiceApi.md#listtoinsurancesunsent) | **GET** /rest/v2/invoice/toInsurances/unsent | Gets all invoices for author at date
*InvoiceApi* | [**listToPatients**](docs/InvoiceApi.md#listtopatients) | **GET** /rest/v2/invoice/toPatients | Gets all invoices for author at date
*InvoiceApi* | [**listToPatientsUnsent**](docs/InvoiceApi.md#listtopatientsunsent) | **GET** /rest/v2/invoice/toPatients/unsent | Gets all invoices for author at date
*InvoiceApi* | [**mergeTo**](docs/InvoiceApi.md#mergeto) | **POST** /rest/v2/invoice/mergeTo/{invoiceId} | Gets all invoices for author at date
*InvoiceApi* | [**modifyInvoice**](docs/InvoiceApi.md#modifyinvoice) | **PUT** /rest/v2/invoice | Modifies an invoice
*InvoiceApi* | [**modifyInvoices**](docs/InvoiceApi.md#modifyinvoices) | **PUT** /rest/v2/invoice/batch | Modify a batch of invoices
*InvoiceApi* | [**newInvoiceDelegations**](docs/InvoiceApi.md#newinvoicedelegations) | **PUT** /rest/v2/invoice/{invoiceId}/delegate | Adds a delegation to a invoice
*InvoiceApi* | [**reassignInvoice**](docs/InvoiceApi.md#reassigninvoice) | **POST** /rest/v2/invoice/reassign | Modifies an invoice
*InvoiceApi* | [**removeCodes**](docs/InvoiceApi.md#removecodes) | **POST** /rest/v2/invoice/byauthor/{userId}/service/{serviceId} | Remove an invoice of an user
*InvoiceApi* | [**setInvoicesDelegations**](docs/InvoiceApi.md#setinvoicesdelegations) | **POST** /rest/v2/invoice/delegations | Update delegations in healthElements.
*InvoiceApi* | [**validate**](docs/InvoiceApi.md#validate) | **POST** /rest/v2/invoice/validate/{invoiceId} | Gets all invoices for author at date
*KeywordApi* | [**createKeyword**](docs/KeywordApi.md#createkeyword) | **POST** /rest/v2/keyword | Create a keyword with the current user
*KeywordApi* | [**deleteKeywords**](docs/KeywordApi.md#deletekeywords) | **POST** /rest/v2/keyword/delete/batch | Delete keywords.
*KeywordApi* | [**getKeyword**](docs/KeywordApi.md#getkeyword) | **GET** /rest/v2/keyword/{keywordId} | Get a keyword
*KeywordApi* | [**getKeywords**](docs/KeywordApi.md#getkeywords) | **GET** /rest/v2/keyword | Gets all keywords
*KeywordApi* | [**getKeywordsByUser**](docs/KeywordApi.md#getkeywordsbyuser) | **GET** /rest/v2/keyword/byUser/{userId} | Get keywords by user
*KeywordApi* | [**modifyKeyword**](docs/KeywordApi.md#modifykeyword) | **PUT** /rest/v2/keyword | Modify a keyword
*MedexApi* | [**generateMedex**](docs/MedexApi.md#generatemedex) | **POST** /rest/v2/medex/generate | Generate a Medex XML String
*MedicalLocationApi* | [**createMedicalLocation**](docs/MedicalLocationApi.md#createmedicallocation) | **POST** /rest/v2/medicallocation | Creates a medical location
*MedicalLocationApi* | [**deleteMedicalLocations**](docs/MedicalLocationApi.md#deletemedicallocations) | **POST** /rest/v2/medicallocation/delete/batch | Deletes medical locations
*MedicalLocationApi* | [**getMedicalLocation**](docs/MedicalLocationApi.md#getmedicallocation) | **GET** /rest/v2/medicallocation/{locationId} | Gets a medical location
*MedicalLocationApi* | [**getMedicalLocations**](docs/MedicalLocationApi.md#getmedicallocations) | **GET** /rest/v2/medicallocation | Gets all medical locations
*MedicalLocationApi* | [**modifyMedicalLocation**](docs/MedicalLocationApi.md#modifymedicallocation) | **PUT** /rest/v2/medicallocation | Modifies a medical location
*MessageApi* | [**createMessage**](docs/MessageApi.md#createmessage) | **POST** /rest/v2/message | Creates a message
*MessageApi* | [**deleteDelegation**](docs/MessageApi.md#deletedelegation) | **DELETE** /rest/v2/message/{messageId}/delegate/{delegateId} | Deletes a message delegation
*MessageApi* | [**deleteMessages**](docs/MessageApi.md#deletemessages) | **POST** /rest/v2/message/delete/batch | Deletes multiple messages
*MessageApi* | [**findMessages**](docs/MessageApi.md#findmessages) | **GET** /rest/v2/message | Get all messages (paginated) for current HC Party
*MessageApi* | [**findMessagesByFromAddress**](docs/MessageApi.md#findmessagesbyfromaddress) | **GET** /rest/v2/message/byFromAddress | Get all messages (paginated) for current HC Party and provided from address
*MessageApi* | [**findMessagesByHCPartyPatientForeignKeys**](docs/MessageApi.md#findmessagesbyhcpartypatientforeignkeys) | **GET** /rest/v2/message/byHcPartySecretForeignKeys | List messages found By Healthcare Party and secret foreign keys.
*MessageApi* | [**findMessagesByToAddress**](docs/MessageApi.md#findmessagesbytoaddress) | **GET** /rest/v2/message/byToAddress | Get all messages (paginated) for current HC Party and provided to address
*MessageApi* | [**findMessagesByTransportGuid**](docs/MessageApi.md#findmessagesbytransportguid) | **GET** /rest/v2/message/byTransportGuid | Get all messages (paginated) for current HC Party and provided transportGuid
*MessageApi* | [**findMessagesByTransportGuidSentDate**](docs/MessageApi.md#findmessagesbytransportguidsentdate) | **GET** /rest/v2/message/byTransportGuidSentDate | Get all messages starting by a prefix between two date
*MessageApi* | [**getChildrenMessages**](docs/MessageApi.md#getchildrenmessages) | **GET** /rest/v2/message/{messageId}/children | Get children messages of provided message
*MessageApi* | [**getMessage**](docs/MessageApi.md#getmessage) | **GET** /rest/v2/message/{messageId} | Gets a message
*MessageApi* | [**getMessagesChildren**](docs/MessageApi.md#getmessageschildren) | **POST** /rest/v2/message/children/batch | Get children messages of provided message
*MessageApi* | [**listMessagesByInvoices**](docs/MessageApi.md#listmessagesbyinvoices) | **POST** /rest/v2/message/byInvoice | Get children messages of provided message
*MessageApi* | [**listMessagesByTransportGuids**](docs/MessageApi.md#listmessagesbytransportguids) | **POST** /rest/v2/message/byTransportGuid/list | Get all messages for current HC Party and provided transportGuids
*MessageApi* | [**modifyMessage**](docs/MessageApi.md#modifymessage) | **PUT** /rest/v2/message | Updates a message
*MessageApi* | [**newMessageDelegations**](docs/MessageApi.md#newmessagedelegations) | **PUT** /rest/v2/message/{messageId}/delegate | Adds a delegation to a message
*MessageApi* | [**setMessagesReadStatus**](docs/MessageApi.md#setmessagesreadstatus) | **PUT** /rest/v2/message/readstatus | Set read status for given list of messages
*MessageApi* | [**setMessagesStatusBits**](docs/MessageApi.md#setmessagesstatusbits) | **PUT** /rest/v2/message/status/{status} | Set status bits for given list of messages
*PatientApi* | [**countOfPatients**](docs/PatientApi.md#countofpatients) | **GET** /rest/v2/patient/hcParty/{hcPartyId}/count | Get count of patients for a specific HcParty or for the current HcParty 
*PatientApi* | [**createPatient**](docs/PatientApi.md#createpatient) | **POST** /rest/v2/patient | Create a patient
*PatientApi* | [**createPatients**](docs/PatientApi.md#createpatients) | **POST** /rest/v2/patient/batch | Create patients in bulk
*PatientApi* | [**deletePatients**](docs/PatientApi.md#deletepatients) | **POST** /rest/v2/patient/delete/batch | Delete patients.
*PatientApi* | [**filterPatientsBy**](docs/PatientApi.md#filterpatientsby) | **POST** /rest/v2/patient/filter | Filter patients for the current user (HcParty) 
*PatientApi* | [**findDeletedPatients**](docs/PatientApi.md#finddeletedpatients) | **GET** /rest/v2/patient/deleted/byDate | Find deleted patients
*PatientApi* | [**findDuplicatesByName**](docs/PatientApi.md#findduplicatesbyname) | **POST** /rest/v2/patient/duplicates/name | Provides a paginated list of patients with duplicate name for an hecparty
*PatientApi* | [**findDuplicatesBySsin**](docs/PatientApi.md#findduplicatesbyssin) | **POST** /rest/v2/patient/duplicates/ssin | Provides a paginated list of patients with duplicate ssin for an hecparty
*PatientApi* | [**findPatientsByAccessLogUserAfterDate**](docs/PatientApi.md#findpatientsbyaccessloguserafterdate) | **GET** /rest/v2/patient/byAccess/{userId} | Get Paginated List of Patients sorted by Access logs descending
*PatientApi* | [**findPatientsByHealthcareParty**](docs/PatientApi.md#findpatientsbyhealthcareparty) | **GET** /rest/v2/patient | List patients for a specific HcParty
*PatientApi* | [**findPatientsByNameBirthSsinAuto**](docs/PatientApi.md#findpatientsbynamebirthssinauto) | **GET** /rest/v2/patient/byNameBirthSsinAuto | Find patients for the current user (HcParty) 
*PatientApi* | [**findPatientsIdsByHealthcareParty**](docs/PatientApi.md#findpatientsidsbyhealthcareparty) | **GET** /rest/v2/patient/byHcPartyId | List patients by pages for a specific HcParty
*PatientApi* | [**findPatientsModifiedAfter**](docs/PatientApi.md#findpatientsmodifiedafter) | **GET** /rest/v2/patient/modifiedAfter/{date} | List patients that have been modified after the provided date
*PatientApi* | [**fuzzySearch**](docs/PatientApi.md#fuzzysearch) | **GET** /rest/v2/patient/fuzzy | Filter patients for the current user (HcParty) 
*PatientApi* | [**getPatient**](docs/PatientApi.md#getpatient) | **GET** /rest/v2/patient/{patientId} | Get patient
*PatientApi* | [**getPatientHcPartyKeysForDelegate**](docs/PatientApi.md#getpatienthcpartykeysfordelegate) | **GET** /rest/v2/patient/{patientId}/keys | Get the patient (identified by patientId) hcparty keys. Those keys are AES keys (encrypted) used to share information between HCPs and a patient.
*PatientApi* | [**getPatientAesExchangeKeysForDelegate**](docs/PatientApi.md#getpatientaesexchangekeysfordelegate) | **GET** /rest/v2/patient/{patientId}/aesExchangeKeys | Get the HcParty encrypted AES keys indexed by owner.
*PatientApi* | [**getPatientByExternalId**](docs/PatientApi.md#getpatientbyexternalid) | **GET** /rest/v2/patient/byExternalId/{externalId} | Get the patient having the provided externalId
*PatientApi* | [**getPatientByHealthcarepartyAndIdentifier**](docs/PatientApi.md#getpatientbyhealthcarepartyandidentifier) | **GET** /rest/v2/patient/{hcPartyId}/{id} | Get patient by identifier
*PatientApi* | [**getPatients**](docs/PatientApi.md#getpatients) | **POST** /rest/v2/patient/byIds | Get patients by id
*PatientApi* | [**listDeletedPatientsByName**](docs/PatientApi.md#listdeletedpatientsbyname) | **GET** /rest/v2/patient/deleted/by_name | Find deleted patients
*PatientApi* | [**listOfMergesAfter**](docs/PatientApi.md#listofmergesafter) | **GET** /rest/v2/patient/merges/{date} | List patients that have been merged towards another patient 
*PatientApi* | [**matchPatientsBy**](docs/PatientApi.md#matchpatientsby) | **POST** /rest/v2/patient/match | Get ids of patients matching the provided filter for the current user (HcParty) 
*PatientApi* | [**mergeInto**](docs/PatientApi.md#mergeinto) | **PUT** /rest/v2/patient/mergeInto/{toId}/from/{fromIds} | Merge a series of patients into another patient
*PatientApi* | [**modifyPatient**](docs/PatientApi.md#modifypatient) | **PUT** /rest/v2/patient | Modify a patient
*PatientApi* | [**modifyPatientReferral**](docs/PatientApi.md#modifypatientreferral) | **PUT** /rest/v2/patient/{patientId}/referral/{referralId} | Set a patient referral doctor
*PatientApi* | [**modifyPatients**](docs/PatientApi.md#modifypatients) | **PUT** /rest/v2/patient/batch | Modify patients in bulk
*PatientApi* | [**newPatientDelegations**](docs/PatientApi.md#newpatientdelegations) | **POST** /rest/v2/patient/{patientId}/delegate | Delegates a patients to a healthcare party
*PatientApi* | [**registerPatient**](docs/PatientApi.md#registerpatient) | **POST** /rest/v2/patient/register/forHcp/{hcPartyId}/inGroup/{groupId} | Register a patient
*PatientApi* | [**undeletePatient**](docs/PatientApi.md#undeletepatient) | **PUT** /rest/v2/patient/undelete/{patientIds} | undelete previously deleted patients
*PermissionApi* | [**modifyUserPermissions**](docs/PermissionApi.md#modifyuserpermissions) | **PUT** /rest/v2/permissions/{userId} | Add / Revoke permissions to user
*PlaceApi* | [**createPlace**](docs/PlaceApi.md#createplace) | **POST** /rest/v2/place | Creates a place
*PlaceApi* | [**deletePlaces**](docs/PlaceApi.md#deleteplaces) | **POST** /rest/v2/place/delete/batch | Deletes places
*PlaceApi* | [**getPlace**](docs/PlaceApi.md#getplace) | **GET** /rest/v2/place/{placeId} | Gets an place
*PlaceApi* | [**getPlaces**](docs/PlaceApi.md#getplaces) | **GET** /rest/v2/place | Gets all places
*PlaceApi* | [**modifyPlace**](docs/PlaceApi.md#modifyplace) | **PUT** /rest/v2/place | Modifies an place
*ReceiptApi* | [**createReceipt**](docs/ReceiptApi.md#createreceipt) | **POST** /rest/v2/receipt | Creates a receipt
*ReceiptApi* | [**deleteReceipts**](docs/ReceiptApi.md#deletereceipts) | **POST** /rest/v2/receipt/delete/batch | Deletes receipts
*ReceiptApi* | [**getReceipt**](docs/ReceiptApi.md#getreceipt) | **GET** /rest/v2/receipt/{receiptId} | Gets a receipt
*ReceiptApi* | [**getReceiptAttachment**](docs/ReceiptApi.md#getreceiptattachment) | **GET** /rest/v2/receipt/{receiptId}/attachment/{attachmentId} | Get an attachment
*ReceiptApi* | [**listByReference**](docs/ReceiptApi.md#listbyreference) | **GET** /rest/v2/receipt/byRef/{ref} | Gets a receipt
*ReceiptApi* | [**modifyReceipt**](docs/ReceiptApi.md#modifyreceipt) | **PUT** /rest/v2/receipt | Updates a receipt
*ReceiptApi* | [**setReceiptAttachment**](docs/ReceiptApi.md#setreceiptattachment) | **PUT** /rest/v2/receipt/{receiptId}/attachment/{blobType} | Creates a receipt's attachment
*TarificationApi* | [**createTarification**](docs/TarificationApi.md#createtarification) | **POST** /rest/v2/tarification | Create a Tarification
*TarificationApi* | [**findTarificationsBy**](docs/TarificationApi.md#findtarificationsby) | **GET** /rest/v2/tarification | Finding tarifications by tarification, type and version with pagination.
*TarificationApi* | [**findTarificationsBy1**](docs/TarificationApi.md#findtarificationsby1) | **GET** /rest/v2/tarification/byRegionTypeTarification | Finding tarifications by tarification, type and version
*TarificationApi* | [**findTarificationsByLabel**](docs/TarificationApi.md#findtarificationsbylabel) | **GET** /rest/v2/tarification/byLabel | Finding tarifications by tarification, type and version with pagination.
*TarificationApi* | [**getTarification**](docs/TarificationApi.md#gettarification) | **GET** /rest/v2/tarification/{tarificationId} | Get a tarification
*TarificationApi* | [**getTarificationWithParts**](docs/TarificationApi.md#gettarificationwithparts) | **GET** /rest/v2/tarification/{type}/{tarification}/{version} | Get a tarification
*TarificationApi* | [**getTarifications**](docs/TarificationApi.md#gettarifications) | **POST** /rest/v2/tarification/byIds | Get a list of tarifications by ids
*TarificationApi* | [**modifyTarification**](docs/TarificationApi.md#modifytarification) | **PUT** /rest/v2/tarification | Modify a tarification
*TimeTableApi* | [**createTimeTable**](docs/TimeTableApi.md#createtimetable) | **POST** /rest/v2/timeTable | Creates a timeTable
*TimeTableApi* | [**deleteTimeTable**](docs/TimeTableApi.md#deletetimetable) | **POST** /rest/v2/timeTable/delete/batch | Deletes an timeTable
*TimeTableApi* | [**getTimeTable**](docs/TimeTableApi.md#gettimetable) | **GET** /rest/v2/timeTable/{timeTableId} | Gets a timeTable
*TimeTableApi* | [**getTimeTablesByAgendaId**](docs/TimeTableApi.md#gettimetablesbyagendaid) | **POST** /rest/v2/timeTable/byAgendaId | Get TimeTables by AgendaId
*TimeTableApi* | [**getTimeTablesByPeriodAndAgendaId**](docs/TimeTableApi.md#gettimetablesbyperiodandagendaid) | **POST** /rest/v2/timeTable/byPeriodAndAgendaId | Get TimeTables by Period and AgendaId
*TimeTableApi* | [**modifyTimeTable**](docs/TimeTableApi.md#modifytimetable) | **PUT** /rest/v2/timeTable | Modifies an timeTable
*TmpApi* | [**createTmpClassification**](docs/TmpApi.md#createtmpclassification) | **POST** /rest/v2/tmp/classification | Create a classification with the current user
*TmpApi* | [**createTmpClassifications**](docs/TmpApi.md#createtmpclassifications) | **POST** /rest/v2/tmp/classification/batch | Create a classification with the current user
*TmpApi* | [**createTmpContact**](docs/TmpApi.md#createtmpcontact) | **POST** /rest/v2/tmp/contact | Create a contact with the current user
*TmpApi* | [**createTmpContacts**](docs/TmpApi.md#createtmpcontacts) | **POST** /rest/v2/tmp/contact/batch | Create a contact with the current user
*TmpApi* | [**createTmpDatabase**](docs/TmpApi.md#createtmpdatabase) | **POST** /rest/v2/tmp | Create tmp database for current user
*TmpApi* | [**createTmpDocument**](docs/TmpApi.md#createtmpdocument) | **POST** /rest/v2/tmp/document | Create a document with the current user
*TmpApi* | [**createTmpDocuments**](docs/TmpApi.md#createtmpdocuments) | **POST** /rest/v2/tmp/document/batch | Create a document with the current user
*TmpApi* | [**createTmpEntityTemplate**](docs/TmpApi.md#createtmpentitytemplate) | **POST** /rest/v2/tmp/entityTemplate | Create a entityTemplate with the current user
*TmpApi* | [**createTmpEntityTemplates**](docs/TmpApi.md#createtmpentitytemplates) | **POST** /rest/v2/tmp/entityTemplate/batch | Create a entityTemplate with the current user
*TmpApi* | [**createTmpForm**](docs/TmpApi.md#createtmpform) | **POST** /rest/v2/tmp/form | Create a form with the current user
*TmpApi* | [**createTmpForms**](docs/TmpApi.md#createtmpforms) | **POST** /rest/v2/tmp/form/batch | Create a form with the current user
*TmpApi* | [**createTmpHealthElement**](docs/TmpApi.md#createtmphealthelement) | **POST** /rest/v2/tmp/healthElement | Create a healthElement with the current user
*TmpApi* | [**createTmpHealthElements**](docs/TmpApi.md#createtmphealthelements) | **POST** /rest/v2/tmp/healthElement/batch | Create a healthElement with the current user
*TmpApi* | [**createTmpInvoice**](docs/TmpApi.md#createtmpinvoice) | **POST** /rest/v2/tmp/invoice | Create a invoice with the current user
*TmpApi* | [**createTmpInvoices**](docs/TmpApi.md#createtmpinvoices) | **POST** /rest/v2/tmp/invoice/batch | Create a invoice with the current user
*TmpApi* | [**createTmpMessage**](docs/TmpApi.md#createtmpmessage) | **POST** /rest/v2/tmp/message | Create a message with the current user
*TmpApi* | [**createTmpMessages**](docs/TmpApi.md#createtmpmessages) | **POST** /rest/v2/tmp/message/batch | Create a message with the current user
*TmpApi* | [**createTmpPatient**](docs/TmpApi.md#createtmppatient) | **POST** /rest/v2/tmp/patient | Create a patient with the current user
*TmpApi* | [**createTmpPatients**](docs/TmpApi.md#createtmppatients) | **POST** /rest/v2/tmp/patient/batch | Create a patient with the current user
*TmpApi* | [**deleteTmpItems**](docs/TmpApi.md#deletetmpitems) | **POST** /rest/v2/tmp/batch/delete | Soft delete items.
*TmpApi* | [**destroyTmpDatabase**](docs/TmpApi.md#destroytmpdatabase) | **DELETE** /rest/v2/tmp | Destroy tmp database for current user
*TmpApi* | [**getTmpClassification**](docs/TmpApi.md#gettmpclassification) | **GET** /rest/v2/tmp/classification/byId/{id} | Get a classification by id
*TmpApi* | [**getTmpClassifications**](docs/TmpApi.md#gettmpclassifications) | **POST** /rest/v2/tmp/classification/get | Get classifications by ids with the current user
*TmpApi* | [**getTmpContact**](docs/TmpApi.md#gettmpcontact) | **GET** /rest/v2/tmp/contact/byId/{id} | Get a contact by id
*TmpApi* | [**getTmpContacts**](docs/TmpApi.md#gettmpcontacts) | **POST** /rest/v2/tmp/contact/get | Get contacts by ids with the current user
*TmpApi* | [**getTmpDocument**](docs/TmpApi.md#gettmpdocument) | **GET** /rest/v2/tmp/document/byId/{id} | Get a document by id
*TmpApi* | [**getTmpDocuments**](docs/TmpApi.md#gettmpdocuments) | **POST** /rest/v2/tmp/document/get | Get documents by ids with the current user
*TmpApi* | [**getTmpEntityTemplate**](docs/TmpApi.md#gettmpentitytemplate) | **GET** /rest/v2/tmp/entityTemplate/byId/{id} | Get a entityTemplate by id
*TmpApi* | [**getTmpEntityTemplates**](docs/TmpApi.md#gettmpentitytemplates) | **POST** /rest/v2/tmp/entityTemplate/get | Get entityTemplates by ids with the current user
*TmpApi* | [**getTmpForm**](docs/TmpApi.md#gettmpform) | **GET** /rest/v2/tmp/form/byId/{id} | Get a form by id
*TmpApi* | [**getTmpForms**](docs/TmpApi.md#gettmpforms) | **POST** /rest/v2/tmp/form/get | Get forms by ids with the current user
*TmpApi* | [**getTmpHealthElement**](docs/TmpApi.md#gettmphealthelement) | **GET** /rest/v2/tmp/healthElement/byId/{id} | Get a healthElement by id
*TmpApi* | [**getTmpHealthElements**](docs/TmpApi.md#gettmphealthelements) | **POST** /rest/v2/tmp/healthElement/get | Get healthElements by ids with the current user
*TmpApi* | [**getTmpInvoice**](docs/TmpApi.md#gettmpinvoice) | **GET** /rest/v2/tmp/invoice/byId/{id} | Get a invoice by id
*TmpApi* | [**getTmpInvoices**](docs/TmpApi.md#gettmpinvoices) | **POST** /rest/v2/tmp/invoice/get | Get invoices by ids with the current user
*TmpApi* | [**getTmpMessage**](docs/TmpApi.md#gettmpmessage) | **GET** /rest/v2/tmp/message/byId/{id} | Get a message by id
*TmpApi* | [**getTmpMessages**](docs/TmpApi.md#gettmpmessages) | **POST** /rest/v2/tmp/message/get | Get messages by ids with the current user
*TmpApi* | [**getTmpPatient**](docs/TmpApi.md#gettmppatient) | **GET** /rest/v2/tmp/patient/byId/{id} | Get a patient by id
*TmpApi* | [**getTmpPatients**](docs/TmpApi.md#gettmppatients) | **POST** /rest/v2/tmp/patient/get | Get patients by ids with the current user
*TmpApi* | [**listTmpClassifications**](docs/TmpApi.md#listtmpclassifications) | **GET** /rest/v2/tmp/classification/list | List classifications with the current user
*TmpApi* | [**listTmpContacts**](docs/TmpApi.md#listtmpcontacts) | **GET** /rest/v2/tmp/contact/list | List contacts with the current user
*TmpApi* | [**listTmpDocuments**](docs/TmpApi.md#listtmpdocuments) | **GET** /rest/v2/tmp/document/list | List documents with the current user
*TmpApi* | [**listTmpEntityTemplates**](docs/TmpApi.md#listtmpentitytemplates) | **GET** /rest/v2/tmp/entityTemplate/list | List entityTemplates with the current user
*TmpApi* | [**listTmpForms**](docs/TmpApi.md#listtmpforms) | **GET** /rest/v2/tmp/form/list | List forms with the current user
*TmpApi* | [**listTmpHealthElements**](docs/TmpApi.md#listtmphealthelements) | **GET** /rest/v2/tmp/healthElement/list | List healthElements with the current user
*TmpApi* | [**listTmpInvoices**](docs/TmpApi.md#listtmpinvoices) | **GET** /rest/v2/tmp/invoice/list | List invoices with the current user
*TmpApi* | [**listTmpMessages**](docs/TmpApi.md#listtmpmessages) | **GET** /rest/v2/tmp/message/list | List messages with the current user
*TmpApi* | [**listTmpPatients**](docs/TmpApi.md#listtmppatients) | **GET** /rest/v2/tmp/patient/list | List patients with the current user
*TmpApi* | [**modifyTmpClassification**](docs/TmpApi.md#modifytmpclassification) | **PUT** /rest/v2/tmp/classification | Modify a classification
*TmpApi* | [**modifyTmpClassifications**](docs/TmpApi.md#modifytmpclassifications) | **PUT** /rest/v2/tmp/classification/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpContact**](docs/TmpApi.md#modifytmpcontact) | **PUT** /rest/v2/tmp/contact | Modify a contact
*TmpApi* | [**modifyTmpContacts**](docs/TmpApi.md#modifytmpcontacts) | **PUT** /rest/v2/tmp/contact/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpDocument**](docs/TmpApi.md#modifytmpdocument) | **PUT** /rest/v2/tmp/document | Modify a document
*TmpApi* | [**modifyTmpDocuments**](docs/TmpApi.md#modifytmpdocuments) | **PUT** /rest/v2/tmp/document/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpEntityTemplate**](docs/TmpApi.md#modifytmpentitytemplate) | **PUT** /rest/v2/tmp/entityTemplate | Modify a entityTemplate
*TmpApi* | [**modifyTmpEntityTemplates**](docs/TmpApi.md#modifytmpentitytemplates) | **PUT** /rest/v2/tmp/entityTemplate/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpForm**](docs/TmpApi.md#modifytmpform) | **PUT** /rest/v2/tmp/form | Modify a form
*TmpApi* | [**modifyTmpForms**](docs/TmpApi.md#modifytmpforms) | **PUT** /rest/v2/tmp/form/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpHealthElement**](docs/TmpApi.md#modifytmphealthelement) | **PUT** /rest/v2/tmp/healthElement | Modify a healthElement
*TmpApi* | [**modifyTmpHealthElements**](docs/TmpApi.md#modifytmphealthelements) | **PUT** /rest/v2/tmp/healthElement/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpInvoice**](docs/TmpApi.md#modifytmpinvoice) | **PUT** /rest/v2/tmp/invoice | Modify a invoice
*TmpApi* | [**modifyTmpInvoices**](docs/TmpApi.md#modifytmpinvoices) | **PUT** /rest/v2/tmp/invoice/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpMessage**](docs/TmpApi.md#modifytmpmessage) | **PUT** /rest/v2/tmp/message | Modify a message
*TmpApi* | [**modifyTmpMessages**](docs/TmpApi.md#modifytmpmessages) | **PUT** /rest/v2/tmp/message/batch | Modify a batch of healthcare elements
*TmpApi* | [**modifyTmpPatient**](docs/TmpApi.md#modifytmppatient) | **PUT** /rest/v2/tmp/patient | Modify a patient
*TmpApi* | [**modifyTmpPatients**](docs/TmpApi.md#modifytmppatients) | **PUT** /rest/v2/tmp/patient/batch | Modify a batch of healthcare elements
*TmpApi* | [**purgeTmpItems**](docs/TmpApi.md#purgetmpitems) | **POST** /rest/v2/tmp/batch/purge | Hard delete items.
*TmpApi* | [**replicateToTmpDatabase**](docs/TmpApi.md#replicatetotmpdatabase) | **POST** /rest/v2/tmp/replicate/from/{from} | 
*UserApi* | [**assignHealthcareParty**](docs/UserApi.md#assignhealthcareparty) | **PUT** /rest/v2/user/current/hcparty/{healthcarePartyId} | Assign a healthcare party ID to current user
*UserApi* | [**checkPassword**](docs/UserApi.md#checkpassword) | **GET** /rest/v2/user/checkPassword | 
*UserApi* | [**checkTokenValidity**](docs/UserApi.md#checktokenvalidity) | **GET** /rest/v2/user/token/{userId} | Check token validity
*UserApi* | [**createUser**](docs/UserApi.md#createuser) | **POST** /rest/v2/user | Create a user
*UserApi* | [**createUserInGroup**](docs/UserApi.md#createuseringroup) | **POST** /rest/v2/user/inGroup/{groupId} | Create a user
*UserApi* | [**deleteUser**](docs/UserApi.md#deleteuser) | **DELETE** /rest/v2/user/{userId} | Delete a User based on his/her ID.
*UserApi* | [**deleteUserInGroup**](docs/UserApi.md#deleteuseringroup) | **DELETE** /rest/v2/user/inGroup/{groupId}/{userId} | Delete a User based on his/her ID.
*UserApi* | [**encodePassword**](docs/UserApi.md#encodepassword) | **GET** /rest/v2/user/encodePassword | 
*UserApi* | [**filterUsersBy**](docs/UserApi.md#filterusersby) | **POST** /rest/v2/user/filter | Filter users for the current user (HcParty)
*UserApi* | [**filterUsersInGroupBy**](docs/UserApi.md#filterusersingroupby) | **POST** /rest/v2/user/filter/inGroup/{groupId} | Filter users for the current user (HcParty) for a provided groupId
*UserApi* | [**findByHcpartyId**](docs/UserApi.md#findbyhcpartyid) | **GET** /rest/v2/user/byHealthcarePartyId/{id} | Get the list of users by healthcare party id
*UserApi* | [**getCurrentSession**](docs/UserApi.md#getcurrentsession) | **GET** /rest/v2/user/session | Get Currently logged-in user session.
*UserApi* | [**getCurrentUser**](docs/UserApi.md#getcurrentuser) | **GET** /rest/v2/user/current | Get presently logged-in user.
*UserApi* | [**getMatchingUsers**](docs/UserApi.md#getmatchingusers) | **GET** /rest/v2/user/matches | Get presently logged-in user.
*UserApi* | [**getToken**](docs/UserApi.md#gettoken) | **POST** /rest/v2/user/token/{userId}/{key} | Request a new temporary token for authentication
*UserApi* | [**getTokenInAllGroups**](docs/UserApi.md#gettokeninallgroups) | **POST** /rest/v2/user/inAllGroups/token/{userIdentifier}/{key} | Require a new temporary token for authentication inside all groups
*UserApi* | [**getTokenInGroup**](docs/UserApi.md#gettokeningroup) | **POST** /rest/v2/user/inGroup/{groupId}/token/{userId}/{key} | Require a new temporary token for authentication inside provided group
*UserApi* | [**getUser**](docs/UserApi.md#getuser) | **GET** /rest/v2/user/{userId} | Get a user by his ID
*UserApi* | [**getUserByEmail**](docs/UserApi.md#getuserbyemail) | **GET** /rest/v2/user/byEmail/{email} | Get a user by his Email/Login
*UserApi* | [**listUsersBy**](docs/UserApi.md#listusersby) | **GET** /rest/v2/user | List users with(out) pagination
*UserApi* | [**listUsersInGroup**](docs/UserApi.md#listusersingroup) | **GET** /rest/v2/user/inGroup/{groupId} | List users with(out) pagination
*UserApi* | [**matchUsersBy**](docs/UserApi.md#matchusersby) | **POST** /rest/v2/user/match | Get ids of healthcare party matching the provided filter for the current user (HcParty) 
*UserApi* | [**modifyProperties**](docs/UserApi.md#modifyproperties) | **PUT** /rest/v2/user/{userId}/properties | Modify a User property
*UserApi* | [**modifyUser**](docs/UserApi.md#modifyuser) | **PUT** /rest/v2/user | Modify a user.
*UserApi* | [**modifyUserInGroup**](docs/UserApi.md#modifyuseringroup) | **PUT** /rest/v2/user/inGroup/{groupId} | Modify a user.


<a name="documentation-for-models"></a>
## Documentation for Models

 - [io.icure.kraken.client.models.AbstractFilterDtoCode](docs/AbstractFilterDtoCode.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoContact](docs/AbstractFilterDtoContact.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoDevice](docs/AbstractFilterDtoDevice.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoHealthElement](docs/AbstractFilterDtoHealthElement.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoHealthcareParty](docs/AbstractFilterDtoHealthcareParty.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoInvoice](docs/AbstractFilterDtoInvoice.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoPatient](docs/AbstractFilterDtoPatient.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoService](docs/AbstractFilterDtoService.md)
 - [io.icure.kraken.client.models.AbstractFilterDtoUser](docs/AbstractFilterDtoUser.md)
 - [io.icure.kraken.client.models.AccessLogDto](docs/AccessLogDto.md)
 - [io.icure.kraken.client.models.AddedDocumentDto](docs/AddedDocumentDto.md)
 - [io.icure.kraken.client.models.AddressDto](docs/AddressDto.md)
 - [io.icure.kraken.client.models.AdministrationQuantity](docs/AdministrationQuantity.md)
 - [io.icure.kraken.client.models.AgendaDto](docs/AgendaDto.md)
 - [io.icure.kraken.client.models.AgreementAppendixDto](docs/AgreementAppendixDto.md)
 - [io.icure.kraken.client.models.AmpComponentDto](docs/AmpComponentDto.md)
 - [io.icure.kraken.client.models.AmpDto](docs/AmpDto.md)
 - [io.icure.kraken.client.models.AmppComponentDto](docs/AmppComponentDto.md)
 - [io.icure.kraken.client.models.AmppDto](docs/AmppDto.md)
 - [io.icure.kraken.client.models.AnnotationDto](docs/AnnotationDto.md)
 - [io.icure.kraken.client.models.ApplicationSettingsDto](docs/ApplicationSettingsDto.md)
 - [io.icure.kraken.client.models.AppointmentTypeAndPlaceDto](docs/AppointmentTypeAndPlaceDto.md)
 - [io.icure.kraken.client.models.ArticleDto](docs/ArticleDto.md)
 - [io.icure.kraken.client.models.AtcDto](docs/AtcDto.md)
 - [io.icure.kraken.client.models.AuthenticationResponse](docs/AuthenticationResponse.md)
 - [io.icure.kraken.client.models.AuthenticationTokenDto](docs/AuthenticationTokenDto.md)
 - [io.icure.kraken.client.models.BasicDto](docs/BasicDto.md)
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
 - [io.icure.kraken.client.models.DataOwnerRegistrationSuccessDto](docs/DataOwnerRegistrationSuccessDto.md)
 - [io.icure.kraken.client.models.DatabaseInfoDto](docs/DatabaseInfoDto.md)
 - [io.icure.kraken.client.models.DatabaseInitialisationDto](docs/DatabaseInitialisationDto.md)
 - [io.icure.kraken.client.models.DatabaseSynchronizationDto](docs/DatabaseSynchronizationDto.md)
 - [io.icure.kraken.client.models.DelegationDto](docs/DelegationDto.md)
 - [io.icure.kraken.client.models.DeviceDto](docs/DeviceDto.md)
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
 - [io.icure.kraken.client.models.EmployerDto](docs/EmployerDto.md)
 - [io.icure.kraken.client.models.EmploymentInfoDto](docs/EmploymentInfoDto.md)
 - [io.icure.kraken.client.models.EntityReferenceDto](docs/EntityReferenceDto.md)
 - [io.icure.kraken.client.models.EntityTemplateDto](docs/EntityTemplateDto.md)
 - [io.icure.kraken.client.models.EpisodeDto](docs/EpisodeDto.md)
 - [io.icure.kraken.client.models.FilterChainCode](docs/FilterChainCode.md)
 - [io.icure.kraken.client.models.FilterChainContact](docs/FilterChainContact.md)
 - [io.icure.kraken.client.models.FilterChainDevice](docs/FilterChainDevice.md)
 - [io.icure.kraken.client.models.FilterChainHealthElement](docs/FilterChainHealthElement.md)
 - [io.icure.kraken.client.models.FilterChainHealthcareParty](docs/FilterChainHealthcareParty.md)
 - [io.icure.kraken.client.models.FilterChainInvoice](docs/FilterChainInvoice.md)
 - [io.icure.kraken.client.models.FilterChainPatient](docs/FilterChainPatient.md)
 - [io.icure.kraken.client.models.FilterChainService](docs/FilterChainService.md)
 - [io.icure.kraken.client.models.FilterChainUser](docs/FilterChainUser.md)
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
 - [io.icure.kraken.client.models.GroupDatabasesInfoDto](docs/GroupDatabasesInfoDto.md)
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
 - [io.icure.kraken.client.models.IncapacityExportInfoDto](docs/IncapacityExportInfoDto.md)
 - [io.icure.kraken.client.models.IndexingInfoDto](docs/IndexingInfoDto.md)
 - [io.icure.kraken.client.models.IngredientDto](docs/IngredientDto.md)
 - [io.icure.kraken.client.models.InlineResponse200](docs/InlineResponse200.md)
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
 - [io.icure.kraken.client.models.LoginCredentials](docs/LoginCredentials.md)
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
 - [io.icure.kraken.client.models.PaginatedListDeviceDto](docs/PaginatedListDeviceDto.md)
 - [io.icure.kraken.client.models.PaginatedListDocumentDto](docs/PaginatedListDocumentDto.md)
 - [io.icure.kraken.client.models.PaginatedListEntityTemplateDto](docs/PaginatedListEntityTemplateDto.md)
 - [io.icure.kraken.client.models.PaginatedListFormDto](docs/PaginatedListFormDto.md)
 - [io.icure.kraken.client.models.PaginatedListGroupDto](docs/PaginatedListGroupDto.md)
 - [io.icure.kraken.client.models.PaginatedListHealthElementDto](docs/PaginatedListHealthElementDto.md)
 - [io.icure.kraken.client.models.PaginatedListHealthcarePartyDto](docs/PaginatedListHealthcarePartyDto.md)
 - [io.icure.kraken.client.models.PaginatedListInvoiceDto](docs/PaginatedListInvoiceDto.md)
 - [io.icure.kraken.client.models.PaginatedListMessageDto](docs/PaginatedListMessageDto.md)
 - [io.icure.kraken.client.models.PaginatedListNmpDto](docs/PaginatedListNmpDto.md)
 - [io.icure.kraken.client.models.PaginatedListPatientDto](docs/PaginatedListPatientDto.md)
 - [io.icure.kraken.client.models.PaginatedListServiceDto](docs/PaginatedListServiceDto.md)
 - [io.icure.kraken.client.models.PaginatedListString](docs/PaginatedListString.md)
 - [io.icure.kraken.client.models.PaginatedListTarificationDto](docs/PaginatedListTarificationDto.md)
 - [io.icure.kraken.client.models.PaginatedListUserDto](docs/PaginatedListUserDto.md)
 - [io.icure.kraken.client.models.PaginatedListVmpDto](docs/PaginatedListVmpDto.md)
 - [io.icure.kraken.client.models.PaginatedListVmpGroupDto](docs/PaginatedListVmpGroupDto.md)
 - [io.icure.kraken.client.models.ParagraphAgreementDto](docs/ParagraphAgreementDto.md)
 - [io.icure.kraken.client.models.ParagraphDto](docs/ParagraphDto.md)
 - [io.icure.kraken.client.models.PartnershipDto](docs/PartnershipDto.md)
 - [io.icure.kraken.client.models.PatientDto](docs/PatientDto.md)
 - [io.icure.kraken.client.models.PatientHealthCarePartyDto](docs/PatientHealthCarePartyDto.md)
 - [io.icure.kraken.client.models.PaymentDto](docs/PaymentDto.md)
 - [io.icure.kraken.client.models.PeriodicityDto](docs/PeriodicityDto.md)
 - [io.icure.kraken.client.models.PermissionDto](docs/PermissionDto.md)
 - [io.icure.kraken.client.models.PermissionItemDto](docs/PermissionItemDto.md)
 - [io.icure.kraken.client.models.PersonNameDto](docs/PersonNameDto.md)
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
 - [io.icure.kraken.client.models.RemoteAuthenticationDto](docs/RemoteAuthenticationDto.md)
 - [io.icure.kraken.client.models.RemoteDto](docs/RemoteDto.md)
 - [io.icure.kraken.client.models.RenewalDto](docs/RenewalDto.md)
 - [io.icure.kraken.client.models.ReplicationDto](docs/ReplicationDto.md)
 - [io.icure.kraken.client.models.ReplicationInfoDto](docs/ReplicationInfoDto.md)
 - [io.icure.kraken.client.models.ReplicationStatsDto](docs/ReplicationStatsDto.md)
 - [io.icure.kraken.client.models.ReplicatorDocumentDto](docs/ReplicatorDocumentDto.md)
 - [io.icure.kraken.client.models.Response](docs/Response.md)
 - [io.icure.kraken.client.models.RestV2BeSamv2ChapChapterNameParagraphNameVerseSeqAddeddocDocSeqLanguageLocale](docs/RestV2BeSamv2ChapChapterNameParagraphNameVerseSeqAddeddocDocSeqLanguageLocale.md)
 - [io.icure.kraken.client.models.RestV2BeSamv2ChapChapterNameParagraphNameVerseSeqAddeddocDocSeqLanguageOutputStream](docs/RestV2BeSamv2ChapChapterNameParagraphNameVerseSeqAddeddocDocSeqLanguageOutputStream.md)
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
 - [io.icure.kraken.client.models.TimeSeriesDto](docs/TimeSeriesDto.md)
 - [io.icure.kraken.client.models.TimeTableDto](docs/TimeTableDto.md)
 - [io.icure.kraken.client.models.TimeTableHourDto](docs/TimeTableHourDto.md)
 - [io.icure.kraken.client.models.TimeTableItemDto](docs/TimeTableItemDto.md)
 - [io.icure.kraken.client.models.TokenWithGroupDto](docs/TokenWithGroupDto.md)
 - [io.icure.kraken.client.models.TypedValueDtoObject](docs/TypedValueDtoObject.md)
 - [io.icure.kraken.client.models.UserAndHealthcarePartyDto](docs/UserAndHealthcarePartyDto.md)
 - [io.icure.kraken.client.models.UserDto](docs/UserDto.md)
 - [io.icure.kraken.client.models.UserGroupDto](docs/UserGroupDto.md)
 - [io.icure.kraken.client.models.ValorisationDto](docs/ValorisationDto.md)
 - [io.icure.kraken.client.models.VerseDto](docs/VerseDto.md)
 - [io.icure.kraken.client.models.VirtualFormDto](docs/VirtualFormDto.md)
 - [io.icure.kraken.client.models.VirtualIngredientDto](docs/VirtualIngredientDto.md)
 - [io.icure.kraken.client.models.VmpComponentDto](docs/VmpComponentDto.md)
 - [io.icure.kraken.client.models.VmpDto](docs/VmpDto.md)
 - [io.icure.kraken.client.models.VmpGroupDto](docs/VmpGroupDto.md)
 - [io.icure.kraken.client.models.VmpGroupStubDto](docs/VmpGroupStubDto.md)
 - [io.icure.kraken.client.models.VmpStubDto](docs/VmpStubDto.md)
 - [io.icure.kraken.client.models.VtmDto](docs/VtmDto.md)
 - [io.icure.kraken.client.models.WadaDto](docs/WadaDto.md)
 - [io.icure.kraken.client.models.Weekday](docs/Weekday.md)


<a name="documentation-for-authorization"></a>
## Documentation for Authorization

<a name="basicSchema"></a>
### basicSchema

- **Type**: HTTP basic authentication

