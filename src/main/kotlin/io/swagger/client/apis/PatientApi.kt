/**
 * iCure Cloud API Documentation
 * Spring shop sample application
 *
 * OpenAPI spec version: v0.0.1
 * 
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */
package io.swagger.client.apis

import io.swagger.client.models.AbstractFilterDtoPatient
import io.swagger.client.models.ContentDto
import io.swagger.client.models.DelegationDto
import io.swagger.client.models.DocIdentifier
import io.swagger.client.models.FilterChainPatient
import io.swagger.client.models.IdWithRevDto
import io.swagger.client.models.ListOfIdsDto
import io.swagger.client.models.PaginatedListPatientDto
import io.swagger.client.models.PaginatedListString
import io.swagger.client.models.PatientDto

import io.swagger.client.infrastructure.*

class PatientApi(basePath: kotlin.String = "https://kraken.icure.dev") : ApiClient(basePath) {

    /**
     * Modify a patient
     * Returns the id and _rev of created patients
     * @param body  
     * @return kotlin.Array<IdWithRevDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun bulkUpdatePatients(body: kotlin.Array<PatientDto>): kotlin.Array<IdWithRevDto> {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/patient/bulk"
        )
        val response = request<kotlin.Array<IdWithRevDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<IdWithRevDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get count of patients for a specific HcParty or for the current HcParty 
     * Returns the count of patients
     * @param hcPartyId Healthcare party id 
     * @return ContentDto
     */
    @Suppress("UNCHECKED_CAST")
    fun countOfPatients(hcPartyId: kotlin.String): ContentDto {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/hcParty/{hcPartyId}/count".replace("{" + "hcPartyId" + "}", "$hcPartyId")
        )
        val response = request<ContentDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as ContentDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Create a patient
     * Name, last name, date of birth, and gender are required. After creation of the patient and obtaining the ID, you need to create an initial delegation.
     * @param body  
     * @return PatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun createPatient(body: PatientDto): PatientDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/patient"
        )
        val response = request<PatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Delete patients.
     * Response is an array containing the ID of deleted patient..
     * @param patientIds  
     * @return kotlin.Array<DocIdentifier>
     */
    @Suppress("UNCHECKED_CAST")
    fun deletePatient(patientIds: kotlin.String): kotlin.Array<DocIdentifier> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.DELETE,
                "/rest/v1/patient/{patientIds}".replace("{" + "patientIds" + "}", "$patientIds")
        )
        val response = request<kotlin.Array<DocIdentifier>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<DocIdentifier>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Filter patients for the current user (HcParty) 
     * Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.
     * @param body  
     * @param startKey The start key for pagination, depends on the filters used (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional)
     * @param skip Skip rows (optional)
     * @param sort Sort key (optional)
     * @param desc Descending (optional)
     * @return PaginatedListPatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun filterPatientsBy(body: FilterChainPatient, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null, skip: kotlin.Int? = null, sort: kotlin.String? = null, desc: kotlin.Boolean? = null): PaginatedListPatientDto {
        val localVariableBody: kotlin.Any? = body
        val localVariableQuery: MultiValueMap = mapOf("startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"), "skip" to listOf("$skip"), "sort" to listOf("$sort"), "desc" to listOf("$desc"))
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/patient/filter", query = localVariableQuery
        )
        val response = request<PaginatedListPatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListPatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get Paginated List of Patients sorted by Access logs descending
     * 
     * @param userId A User ID 
     * @param accessType The type of access (COMPUTER or USER) (optional)
     * @param startDate The start search epoch (optional)
     * @param startKey The start key for pagination (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional, default to 1000)
     * @return PaginatedListPatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun findByAccessLogUserAfterDate(userId: kotlin.String, accessType: kotlin.String? = null, startDate: kotlin.Long? = null, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null): PaginatedListPatientDto {
        val localVariableQuery: MultiValueMap = mapOf("accessType" to listOf("$accessType"), "startDate" to listOf("$startDate"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/byAccess/{userId}".replace("{" + "userId" + "}", "$userId"), query = localVariableQuery
        )
        val response = request<PaginatedListPatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListPatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get Paginated List of Patients sorted by Access logs descending
     * 
     * @param externalId A external ID 
     * @return PatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun findByExternalId(externalId: kotlin.String): PatientDto {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/byExternalId/{externalId}".replace("{" + "externalId" + "}", "$externalId")
        )
        val response = request<PatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Find patients for the current user (HcParty) 
     * Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.
     * @param healthcarePartyId HealthcareParty Id, if unset will user user&#x27;s hcpId (optional)
     * @param filterValue Optional value for filtering results (optional)
     * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#x27;s startKey (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional)
     * @param sortDirection Optional value for providing a sorting direction (&#x27;asc&#x27;, &#x27;desc&#x27;). Set to &#x27;asc&#x27; by default. (optional, default to asc)
     * @return PaginatedListPatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun findByNameBirthSsinAuto(healthcarePartyId: kotlin.String? = null, filterValue: kotlin.String? = null, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null, sortDirection: kotlin.String? = null): PaginatedListPatientDto {
        val localVariableQuery: MultiValueMap = mapOf("healthcarePartyId" to listOf("$healthcarePartyId"), "filterValue" to listOf("$filterValue"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"), "sortDirection" to listOf("$sortDirection"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/byNameBirthSsinAuto", query = localVariableQuery
        )
        val response = request<PaginatedListPatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListPatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Filter patients for the current user (HcParty) 
     * Returns a list of patients
     * @param firstName The first name (optional)
     * @param lastName The last name (optional)
     * @param dateOfBirth The date of birth (optional)
     * @return kotlin.Array<PatientDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun fuzzySearch(firstName: kotlin.String? = null, lastName: kotlin.String? = null, dateOfBirth: kotlin.Int? = null): kotlin.Array<PatientDto> {
        val localVariableQuery: MultiValueMap = mapOf("firstName" to listOf("$firstName"), "lastName" to listOf("$lastName"), "dateOfBirth" to listOf("$dateOfBirth"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/fuzzy", query = localVariableQuery
        )
        val response = request<kotlin.Array<PatientDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<PatientDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get patient
     * It gets patient administrative data.
     * @param patientId  
     * @return PatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun getPatient(patientId: kotlin.String): PatientDto {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/{patientId}".replace("{" + "patientId" + "}", "$patientId")
        )
        val response = request<PatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get the patient (identified by patientId) hcparty keys. Those keys are AES keys (encrypted) used to share information between HCPs and a patient.
     * This endpoint is used to recover all keys that have already been created and that can be used to share information with this patient. It returns a map with the following structure: ID of the owner of the encrypted AES key -&gt; encrypted AES key. The returned encrypted AES keys will have to be decrypted using the patient&#x27;s private key.
     * @param patientId The patient Id for which information is shared 
     * @return kotlin.String
     */
    @Suppress("UNCHECKED_CAST")
    fun getPatientHcPartyKeysForDelegate(patientId: kotlin.String): kotlin.String {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/{patientId}/keys".replace("{" + "patientId" + "}", "$patientId")
        )
        val response = request<kotlin.String>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.String
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get patients by id
     * It gets patient administrative data.
     * @param body  
     * @return kotlin.Array<PatientDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun getPatients(body: ListOfIdsDto): kotlin.Array<PatientDto> {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/patient/byIds"
        )
        val response = request<kotlin.Array<PatientDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<PatientDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Find deleted patients
     * Returns a list of deleted patients, within the specified time period, if any.
     * @param startDate Filter deletions after this date (unix epoch), included (optional)
     * @param endDate Filter deletions before this date (unix epoch), included (optional)
     * @param desc Descending (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional)
     * @return PaginatedListPatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun listDeletedPatients(startDate: kotlin.Long? = null, endDate: kotlin.Long? = null, desc: kotlin.Boolean? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null): PaginatedListPatientDto {
        val localVariableQuery: MultiValueMap = mapOf("startDate" to listOf("$startDate"), "endDate" to listOf("$endDate"), "desc" to listOf("$desc"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/deleted/by_date", query = localVariableQuery
        )
        val response = request<PaginatedListPatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListPatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Find deleted patients
     * Returns a list of deleted patients, by name and/or firstname prefix, if any.
     * @param firstName First name prefix (optional)
     * @param lastName Last name prefix (optional)
     * @return kotlin.Array<PatientDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listDeletedPatientsByName(firstName: kotlin.String? = null, lastName: kotlin.String? = null): kotlin.Array<PatientDto> {
        val localVariableQuery: MultiValueMap = mapOf("firstName" to listOf("$firstName"), "lastName" to listOf("$lastName"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/deleted/by_name", query = localVariableQuery
        )
        val response = request<kotlin.Array<PatientDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<PatientDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List patients that have been merged towards another patient 
     * Returns a list of patients that have been merged after the provided date
     * @param date  
     * @return kotlin.Array<PatientDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listOfMergesAfter(date: kotlin.Long): kotlin.Array<PatientDto> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/merges/{date}".replace("{" + "date" + "}", "$date")
        )
        val response = request<kotlin.Array<PatientDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<PatientDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List patients that have been modified after the provided date
     * Returns a list of patients that have been modified after the provided date
     * @param date  
     * @param startKey The start key for pagination the date of the first element of the new page (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional)
     * @return PaginatedListPatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun listOfPatientsModifiedAfter(date: kotlin.Long, startKey: kotlin.Long? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null): PaginatedListPatientDto {
        val localVariableQuery: MultiValueMap = mapOf("startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/modifiedAfter/{date}".replace("{" + "date" + "}", "$date"), query = localVariableQuery
        )
        val response = request<PaginatedListPatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListPatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List patients for a specific HcParty
     * Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.
     * @param hcPartyId Healthcare party id (optional)
     * @param sortField Optional value for sorting results by a given field (&#x27;name&#x27;, &#x27;ssin&#x27;, &#x27;dateOfBirth&#x27;). Specifying this deactivates filtering (optional)
     * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#x27;s startKey (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional)
     * @param sortDirection Optional value for providing a sorting direction (&#x27;asc&#x27;, &#x27;desc&#x27;). Set to &#x27;asc&#x27; by default. (optional, default to asc)
     * @return PaginatedListPatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun listPatients(hcPartyId: kotlin.String? = null, sortField: kotlin.String? = null, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null, sortDirection: kotlin.String? = null): PaginatedListPatientDto {
        val localVariableQuery: MultiValueMap = mapOf("hcPartyId" to listOf("$hcPartyId"), "sortField" to listOf("$sortField"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"), "sortDirection" to listOf("$sortDirection"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient", query = localVariableQuery
        )
        val response = request<PaginatedListPatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListPatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List patients for a specific HcParty or for the current HcParty 
     * Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.
     * @param hcPartyId  
     * @param sortField Optional value for sorting results by a given field (&#x27;name&#x27;, &#x27;ssin&#x27;, &#x27;dateOfBirth&#x27;). Specifying this deactivates filtering (optional)
     * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#x27;s startKey (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional)
     * @param sortDirection Optional value for providing a sorting direction (&#x27;asc&#x27;, &#x27;desc&#x27;). Set to &#x27;asc&#x27; by default. (optional)
     * @return PaginatedListPatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun listPatientsByHcParty(hcPartyId: kotlin.String, sortField: kotlin.String? = null, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null, sortDirection: kotlin.String? = null): PaginatedListPatientDto {
        val localVariableQuery: MultiValueMap = mapOf("sortField" to listOf("$sortField"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"), "sortDirection" to listOf("$sortDirection"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/hcParty/{hcPartyId}".replace("{" + "hcPartyId" + "}", "$hcPartyId"), query = localVariableQuery
        )
        val response = request<PaginatedListPatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListPatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List patients by pages for a specific HcParty
     * Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.
     * @param hcPartyId Healthcare party id 
     * @param startKey The page first id (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Page size (optional)
     * @return PaginatedListString
     */
    @Suppress("UNCHECKED_CAST")
    fun listPatientsIds(hcPartyId: kotlin.String, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null): PaginatedListString {
        val localVariableQuery: MultiValueMap = mapOf("hcPartyId" to listOf("$hcPartyId"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/idsPages", query = localVariableQuery
        )
        val response = request<PaginatedListString>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListString
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List patients of a specific HcParty or of the current HcParty 
     * Returns a list of patients along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.
     * @param hcPartyId  
     * @param sortField Optional value for sorting results by a given field (&#x27;name&#x27;, &#x27;ssin&#x27;, &#x27;dateOfBirth&#x27;). Specifying this deactivates filtering (optional)
     * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#x27;s startKey (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional)
     * @param sortDirection Optional value for providing a sorting direction (&#x27;asc&#x27;, &#x27;desc&#x27;). Set to &#x27;asc&#x27; by default. (optional, default to asc)
     * @return PaginatedListPatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun listPatientsOfHcParty(hcPartyId: kotlin.String, sortField: kotlin.String? = null, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null, sortDirection: kotlin.String? = null): PaginatedListPatientDto {
        val localVariableQuery: MultiValueMap = mapOf("sortField" to listOf("$sortField"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"), "sortDirection" to listOf("$sortDirection"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/patient/ofHcParty/{hcPartyId}".replace("{" + "hcPartyId" + "}", "$hcPartyId"), query = localVariableQuery
        )
        val response = request<PaginatedListPatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListPatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get ids of patients matching the provided filter for the current user (HcParty) 
     * 
     * @param body  
     * @return kotlin.Array<kotlin.String>
     */
    @Suppress("UNCHECKED_CAST")
    fun matchPatientsBy(body: AbstractFilterDtoPatient): kotlin.Array<kotlin.String> {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/patient/match"
        )
        val response = request<kotlin.Array<kotlin.String>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<kotlin.String>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Merge a series of patients into another patient
     * 
     * @param toId  
     * @param fromIds  
     * @return PatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun mergeInto(toId: kotlin.String, fromIds: kotlin.String): PatientDto {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.PUT,
                "/rest/v1/patient/mergeInto/{toId}/from/{fromIds}".replace("{" + "toId" + "}", "$toId").replace("{" + "fromIds" + "}", "$fromIds")
        )
        val response = request<PatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Modify a patient
     * No particular return value. It&#x27;s just a message.
     * @param body  
     * @return PatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun modifyPatient(body: PatientDto): PatientDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.PUT,
                "/rest/v1/patient"
        )
        val response = request<PatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Set a patient referral doctor
     * 
     * @param patientId  
     * @param referralId The referal id. Accepts &#x27;none&#x27; for referral removal. 
     * @param start Optional value for start of referral (optional)
     * @param end Optional value for end of referral (optional)
     * @return PatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun modifyPatientReferral(patientId: kotlin.String, referralId: kotlin.String, start: kotlin.Long? = null, end: kotlin.Long? = null): PatientDto {
        val localVariableQuery: MultiValueMap = mapOf("start" to listOf("$start"), "end" to listOf("$end"))
        val localVariableConfig = RequestConfig(
                RequestMethod.PUT,
                "/rest/v1/patient/{patientId}/referral/{referralId}".replace("{" + "patientId" + "}", "$patientId").replace("{" + "referralId" + "}", "$referralId"), query = localVariableQuery
        )
        val response = request<PatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Delegates a patients to a healthcare party
     * It delegates a patient to a healthcare party (By current healthcare party). A modified patient with new delegation gets returned.
     * @param body  
     * @param patientId  
     * @return PatientDto
     */
    @Suppress("UNCHECKED_CAST")
    fun newPatientDelegations(body: kotlin.Array<DelegationDto>, patientId: kotlin.String): PatientDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/patient/{patientId}/delegate".replace("{" + "patientId" + "}", "$patientId")
        )
        val response = request<PatientDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PatientDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * undelete previously deleted patients
     * Response is an array containing the ID of undeleted patient..
     * @param patientIds  
     * @return kotlin.Array<DocIdentifier>
     */
    @Suppress("UNCHECKED_CAST")
    fun undeletePatient(patientIds: kotlin.String): kotlin.Array<DocIdentifier> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.PUT,
                "/rest/v1/patient/undelete/{patientIds}".replace("{" + "patientIds" + "}", "$patientIds")
        )
        val response = request<kotlin.Array<DocIdentifier>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<DocIdentifier>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
}
