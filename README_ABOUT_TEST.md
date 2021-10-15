# Informations about tests

This paper is made to keep track of differents advancement about tests and explain how to use test in the future.

Last update : 15/10/2021

## How to generate tests ?

To generate tests, you have to execute the `apiGenerate` gradle task 

## How to setup test generation ?

1. Make sure to have the latest version of `openapi-generator-cli.jar` from [icure-openapi-generator](https://bitbucket.taktik.be/projects/ICURE/repos/icure-openapi-generator)
2. VM Options must include an `API_URL` flag, like : `-DAPI_URL=http://localhost:16043`
3. Make sure to provide credentials in thoses files : `.credentialsReadWrite`, `.credentialsReadOnly` and `.credentialsCouchDB`

## Known issues

Due to some limitations and issues, certains tests weren't supported by the first batch generated tests.

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

| Class                   | Endpoint                                          | Reason                                                       |
| ----------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| CodeApiTest             | filterCodesBy                                     | 500 error on back-end                                        |
| CodeApiTest             | findCodesByLink                                   | 500 error on back-end                                        |
| CodeApiTest             | listCodeTypesBy                                   | NPE on CodeApi                                               |
| CodeApiTest             | listTagTypesBy                                    | NPE on CodeApi                                               |
| ContactApiTest          | matchContactsBy                                   | com.fasterxml.jackson.databind.exc.InvalidDefinitionException: Cannot construct instance of `io.icure.kraken.client.models.AbstractFilterDtoContact` (no Creators, like default constructor, exist): abstract types either need to be mapped to concrete types, have custom deserializer, or contain additional type information at [Source: (String)"{"$type":"ContactByHcPartyPatientTagCodeDateFilter","healthcarePartyId":"782f1bcd-9f3f-408a-af1b-cd9f3f908a98","startServiceValueDate":12345}"; line: 1, column: 1] |
| ContactApiTest          | setContactsDelegations                            | TODO                                                         |
| DocumentApiTest         | getDocumentAttachment                             | Something is wrong with attachments                          |
| DocumentApiTest         | setDocumentAttachment                             | Something is wrong with attachments                          |
| DocumentApiTest         | setSafeDocumentAttachment                         | Something is wrong with attachments                          |
| DocumentApiTest         | setDocumentAttachmentMulti                        | Multipart data have no boundaries                            |
| DocumentTemplateApiTest | getDocumentTemplate                               | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot construct instance of `io.icure.kraken.client.infrastructure.ByteArrayWrapper` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value ('eyJlcnJvciI6Im5vdF9mb3VuZCIsInJlYXNvbiI6IkRvY3VtZW50IGlzIG1pc3NpbmcgYXR0YWNobWVudCJ9Cg==')<br/> at [Source: UNKNOWN; line: -1, column: -1] (through reference chain: io.icure.kraken.client.models.DocumentTemplateDto["attachment"]) |
| DocumentTemplateApiTest | listDocumentTemplatesByDocumentType               | Client-side exception 400                                    |
| DocumentTemplateApiTest | listDocumentTemplatesByDocumentTypeForCurrentUser | Client-side exception 400                                    |
| DocumentTemplateApiTest | listDocumentTemplatesBySpeciality                 | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot construct instance of `io.icure.kraken.client.infrastructure.ByteArrayWrapper` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value |
| DocumentTemplateApiTest | listDocumentTemplates                             | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot construct instance of `io.icure.kraken.client.infrastructure.ByteArrayWrapper` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value |
| DocumentTemplateApiTest | setDocumentTemplateAttachmentJson                 | Client-side exception 415                                    |
| DocumentTemplateApiTest | setDocumentTemplateAttachment                     | com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot construct instance of `io.icure.kraken.client.infrastructure.ByteArrayWrapper` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value ('W3siYnl0ZUFycmF5IjoiYUdWc2JHOGdkMjl5YkdRPSIsInNpemUiOjExfV0=') at [Source: UNKNOWN; line: -1, column: -1] (through reference chain: io.icure.kraken.client.models.DocumentTemplateDto["attachment"]) |
| FormApiTest             | *                                                 | TODO                                                         |
|                         |                                                   |                                                              |
|                         |                                                   |                                                              |
|                         |                                                   |                                                              |
|                         |                                                   |                                                              |

## Misc.

Tests are automatically generated along side with infrastructure files :

* `TestUtils.kt`
* `DiffUtils.kt`
* `FilterDeserializer.kt`

