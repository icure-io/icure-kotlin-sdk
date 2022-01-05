# Informations about tests

This paper is made to keep track of different advancement about tests and explain how to use tests in the future.

Last update : 04/01/2022

## How to generate tests ?
To generate tests, you have to execute the `apiGenerate` gradle task. 

This command will execute the `icure-openapi-generator-cli.jar`, which will generate : 
- The API classes;
- The DTO classes;  
- The test classes (not the extended APIs ones !);

This jar is able to do those generation based on the iCure API Specification file () and using the
Mustache OpenAPITemplates in folder **openApiTemplates**. 

If you would like to edit test files, you then need to edit the corresponding mustache template.

## How to setup test generation ?
1. Make sure to have the latest version of `openapi-generator-cli.jar` from [icure-openapi-generator](https://bitbucket.taktik.be/projects/ICURE/repos/icure-openapi-generator)
2. VM Options must include an `API_URL` flag, like : `-DAPI_URL=https://kraken.icure.dev`
3. Make sure to provide credentials in those files : `.credentialsReadWrite`, `.credentialsReadOnly` and `.credentialsCouchDB`

## How to run tests on your local machine ?
### Limitations
For now, tests can only be run under certain conditions which are : 
- With user `abdemotst2` corresponding to hcp `782f1bcd-9f3f-408a-af1b-cd9f3f908a98`, as this is the 
key used to encrypt saved data;
- In the svcacc environment;  

### First-Time Procedure
Here is the procedure to follow the first time you're starting tests. 
Following the environment you would like to query, the following parameters could change a bit. Be careful about the content of it. 

- Start icure-backend on locale machine, pointing on ACCEPTANCE DB.
- At icure-java-client project root, add files `.credentialsReadWrite` and `.credentialsReadOnly` containing credentials of 
  iCure user `abdemotst2`. The content of the file should look like this :
```
{
"username": "abdemotst2",
"password": "USER-PASSWORD"
}
```

- Add file `.credentialsCouchDb` containing credentials of your CouchDB user. This one must be able 
to access the DB `icure-test-2-tz-dev-team`. 
  If you don't have any dedicated user in CouchDB, ask a colleague to explain you how to get one. It can differ 
  following the environment you would like to use, the security to consider, ... 

- When launching your tests, add VM parameter `-ea -DAPI_URL=http://127.0.0.1:16043`

### Validation files
Make sure to have validation files in the proper folder. (eg. `/tmp/icureTests/`) editable by editing the `workingFolder` test class property.

By default, if no validation file are found, the run will generate those validation files.

## Known issues
Due to some limitations and issues, some tests weren't supported by the first batch generated tests.

### Non-supported tests
Some tests classes are deleted just after the generation.

* `ApplicationsettingsApiTest`
* `AuthApiTest`
* `BeefactApiTest`
* `BekmehrApiTest`
* `BeresultexportApiTest`
* `BeresultimportApiTest`
* `Besamv2ApiTest`
* `EntityrefApiTest`
* `IcureApiTest`
* `MedexApiTest`

To avoid/change the deletion of thoses files, you can edit the dedicated gradle task `delete-unused-tests-files`

### Skipped tests
Below, the list of skipped tests and the reason.

| Class                         | Endpoint                                          | Reason                                                       |
| ----------------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| CodeApiTest                   | filterCodesBy                                     | 500 error on back-end                                        |
| CodeApiTest                   | findCodesByLink                                   | 500 error on back-end                                        |
| CodeApiTest                   | listCodeTypesBy                                   | NPE on CodeApi                                               |
| CodeApiTest                   | listTagTypesBy                                    | NPE on CodeApi                                               |
| CodeApiTest                   | findCodesByLabel                                  | totalSize randomly change (probably because the environement is also used by other) |
| ContactApiTest                | matchContactsBy                                   | com.fasterxml.jackson.databind.exc.InvalidDefinitionException: Cannot construct instance of `io.icure.kraken.client.models.AbstractFilterDtoContact` (no Creators, like default constructor, exist): abstract types either need to be mapped to concrete types, have custom deserializer, or contain additional type information at [Source: (String)"{"$type":"ContactByHcPartyPatientTagCodeDateFilter","healthcarePartyId":"782f1bcd-9f3f-408a-af1b-cd9f3f908a98","startServiceValueDate":12345}"; line: 1, column: 1] |
| ContactApiTest                | setContactsDelegations                            | TODO                                                         |
| DocumentApiTest               | getDocumentAttachment                             | Something is wrong with attachments                          |
| DocumentApiTest               | setDocumentAttachment                             | Something is wrong with attachments                          |
| DocumentApiTest               | setSafeDocumentAttachment                         | Something is wrong with attachments                          |
| DocumentApiTest               | setDocumentAttachmentMulti                        | Multipart data have no boundaries                            |
| DocumentTemplateApiTest       | getDocumentTemplate                               | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot construct instance of `io.icure.kraken.client.infrastructure.ByteArrayWrapper` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value ('eyJlcnJvciI6Im5vdF9mb3VuZCIsInJlYXNvbiI6IkRvY3VtZW50IGlzIG1pc3NpbmcgYXR0YWNobWVudCJ9Cg==')<br/> at [Source: UNKNOWN; line: -1, column: -1] (through reference chain: io.icure.kraken.client.models.DocumentTemplateDto["attachment"]) |
| DocumentTemplateApiTest       | listDocumentTemplatesByDocumentType               | Client-side exception 400                                    |
| DocumentTemplateApiTest       | listDocumentTemplatesByDocumentTypeForCurrentUser | Client-side exception 400                                    |
| DocumentTemplateApiTest       | listDocumentTemplatesBySpeciality                 | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot construct instance of `io.icure.kraken.client.infrastructure.ByteArrayWrapper` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value |
| DocumentTemplateApiTest       | listDocumentTemplates                             | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot construct instance of `io.icure.kraken.client.infrastructure.ByteArrayWrapper` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value |
| DocumentTemplateApiTest       | setDocumentTemplateAttachmentJson                 | Client-side exception 415                                    |
| DocumentTemplateApiTest       | setDocumentTemplateAttachment                     | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot construct instance of `io.icure.kraken.client.infrastructure.ByteArrayWrapper` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value ('W3siYnl0ZUFycmF5IjoiYUdWc2JHOGdkMjl5YkdRPSIsInNpemUiOjExfV0=') at [Source: UNKNOWN; line: -1, column: -1] (through reference chain: io.icure.kraken.client.models.DocumentTemplateDto["attachment"]) |
| FormApiTest                   | *                                                 | TODO                                                         |
| CalendarItemApiTest           | setCalendarItemsDelegations                       | TODO                                                         |
| ClassificationApiTest         | setClassificationsDelegations                     | TODO                                                         |
| ClassificationTemplateApiTest | *                                                 | TODO                                                         |
| ContactApiTest                | setContactDelegations                             | TODO                                                         |
| DocumentTemplateApiTest       | setDocumentTemplateAttachmentJson                 | Error with attachment                                        |
| DocumentTemplateApiTest       | listDocumentTemplates                             | TODO                                                         |
| DocumentTemplateApiTest       | listDocumentTemplatesByDocumentType               | TODO                                                         |
| DocumentTemplateApiTest       | listDocumentTemplatesByDocumentTypeForCurrentUser | TODO                                                         |
| DocumentTemplateApiTest       | listDocumentTemplatesBySpeciality                 | TODO                                                         |
| DocumentTemplateApiTest       | getDocumentTemplate                               | TODO                                                         |
| DocumentTemplateApiTest       | setDocumentTemplateAttachment                     | TODO                                                         |
| DocumentTemplateApiTest       | getAttachmentText                                 | Error with attachment                                        |
| DocumentTemplateApiTest       | getDocumentTemplateAttachment                     | Error with attachment                                        |
| EntityTemplateApiTest         | modifyEntityTemplates                             | TODO                                                         |
| EntityTemplateApiTest         | modifyEntityTemplate                              | TODO                                                         |
| EntityTemplateApiTest         | createEntityTemplate                              | TODO                                                         |
| EntityTemplateApiTest         | createEntityTemplates                             | TODO                                                         |
| FormApiTest                   | *                                                 | TODO<br />Need a custom implementation that manage Form and FormTemplate. Actually the beforeElements and afterElements can only handle one entity model. |
| FrontEndMigrationApiTest      | *                                                 | TODO                                                         |
| GroupApiTest                  | *                                                 | TODO<br />Need a custom implementation, the user originaly used can't create  groups for test purpose |
| HealthCarePartyApiTest        | *                                                 | TODO                                                         |
| InvoiceApiTest                | removeCodes                                       | TODO                                                         |
| PatientApiTest                | getPatientHcPartyKeysForDelegate                  | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot deserialize value of type `java.lang.String` from Object value (token `JsonToken.START_OBJECT`) at [Source: UNKNOWN; line: -1, column: -1] |
| PatientApiTest                | listOfMergesAfter                                 | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot construct instance of `io.icure.kraken.client.infrastructure.ByteArrayWrapper` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value ('/9j/4AAQSkZJRgABAQEBLAEsAAD/4QB0RXhpZ...') at [Source: UNKNOWN; line: -1, column: -1] (through reference chain: java.util.ArrayList[42]->io.icure.kraken.client.models.PatientDto["picture"]) |
| PatientApiTest                | matchPatientsBy                                   | com.fasterxml.jackson.databind.exc.InvalidDefinitionException: Cannot construct instance of `io.icure.kraken.client.models.AbstractFilterDtoPatient` (no Creators, like default constructor, exist): abstract types either need to be mapped to concrete types, have custom deserializer, or contain additional type information at [Source: (String)"{"$type":"PatientByHcPartyFilter","healthcarePartyId":"782f1bcd-9f3f-408a-af1b-cd9f3f908a98"}"; line: 1, column: 1] |
| ReceiptApiTest                | getReceiptAttachment                              | Error with attachment                                        |
| UserApiTest                   | *                                                 | TODO<br />Need a custom implementation, the user originally used cannot create users for test purpose. |

## Misc.
Tests are automatically generated alongside with infrastructure files :

* `TestUtils.kt`
* `DiffUtils.kt`
* `FilterDeserializer.kt`

