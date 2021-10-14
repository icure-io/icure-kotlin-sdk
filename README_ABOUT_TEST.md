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

| Class | Endpoint | Reason |
| ----- | -------- | ------ |
|       |          |        |
|       |          |        |
|       |          |        |

## Misc.

Tests are automatically generated along side with infrastructure files :

* `TestUtils.kt`
* `DiffUtils.kt`
* `FilterDeserializer.kt`

