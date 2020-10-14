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

import io.swagger.client.models.DelegationDto
import io.swagger.client.models.DocIdentifier
import io.swagger.client.models.FilterChainInvoice
import io.swagger.client.models.IcureStubDto
import io.swagger.client.models.InvoiceDto
import io.swagger.client.models.InvoicingCodeDto
import io.swagger.client.models.LabelledOccurenceDto
import io.swagger.client.models.ListOfIdsDto
import io.swagger.client.models.PaginatedListInvoiceDto

import io.swagger.client.infrastructure.*

class InvoiceApi(basePath: kotlin.String = "https://kraken.icure.dev") : ApiClient(basePath) {

    /**
     * Gets all invoices for author at date
     * 
     * @param body  
     * @param secretFKeys  
     * @param userId  
     * @param type  
     * @param sentMediumType  
     * @param insuranceId  (optional)
     * @param invoiceId  (optional)
     * @param gracePeriod  (optional)
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun appendCodes(body: kotlin.Array<InvoicingCodeDto>, secretFKeys: kotlin.String, userId: kotlin.String, type: kotlin.String, sentMediumType: kotlin.String, insuranceId: kotlin.String? = null, invoiceId: kotlin.String? = null, gracePeriod: kotlin.Int? = null): kotlin.Array<InvoiceDto> {
        val localVariableBody: kotlin.Any? = body
        val localVariableQuery: MultiValueMap = mapOf("secretFKeys" to listOf("$secretFKeys"), "insuranceId" to listOf("$insuranceId"), "invoiceId" to listOf("$invoiceId"), "gracePeriod" to listOf("$gracePeriod"))
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/byauthor/{userId}/append/{type}/{sentMediumType}".replace("{" + "userId" + "}", "$userId").replace("{" + "type" + "}", "$type").replace("{" + "sentMediumType" + "}", "$sentMediumType"), query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Creates an invoice
     * 
     * @param body  
     * @return InvoiceDto
     */
    @Suppress("UNCHECKED_CAST")
    fun createInvoice(body: InvoiceDto): InvoiceDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice"
        )
        val response = request<InvoiceDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as InvoiceDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Deletes an invoice
     * 
     * @param invoiceId  
     * @return DocIdentifier
     */
    @Suppress("UNCHECKED_CAST")
    fun deleteInvoice(invoiceId: kotlin.String): DocIdentifier {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.DELETE,
                "/rest/v1/invoice/{invoiceId}".replace("{" + "invoiceId" + "}", "$invoiceId")
        )
        val response = request<DocIdentifier>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as DocIdentifier
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Filter invoices for the current user (HcParty)
     * Returns a list of invoices along with next start keys and Document ID. If the nextStartKey is Null it means that this is the last page.
     * @param body  
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun filterInvoicesBy(body: FilterChainInvoice): kotlin.Array<InvoiceDto> {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/filter"
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param hcPartyId  
     * @param fromDate  (optional)
     * @param toDate  (optional)
     * @param startKey The start key for pagination: a JSON representation of an array containing all the necessary components to form the Complex Key&#x27;s startKey (optional)
     * @param startDocumentId A patient document ID (optional)
     * @param limit Number of rows (optional)
     * @return PaginatedListInvoiceDto
     */
    @Suppress("UNCHECKED_CAST")
    fun findByAuthor(hcPartyId: kotlin.String, fromDate: kotlin.Long? = null, toDate: kotlin.Long? = null, startKey: kotlin.String? = null, startDocumentId: kotlin.String? = null, limit: kotlin.Int? = null): PaginatedListInvoiceDto {
        val localVariableQuery: MultiValueMap = mapOf("fromDate" to listOf("$fromDate"), "toDate" to listOf("$toDate"), "startKey" to listOf("$startKey"), "startDocumentId" to listOf("$startDocumentId"), "limit" to listOf("$limit"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/byauthor/{hcPartyId}".replace("{" + "hcPartyId" + "}", "$hcPartyId"), query = localVariableQuery
        )
        val response = request<PaginatedListInvoiceDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as PaginatedListInvoiceDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List invoices found By Healthcare Party and secret foreign patient keys.
     * Keys have to delimited by coma
     * @param hcPartyId  
     * @param secretFKeys  
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun findInvoicesByHCPartyPatientForeignKeys(hcPartyId: kotlin.String, secretFKeys: kotlin.String): kotlin.Array<InvoiceDto> {
        val localVariableQuery: MultiValueMap = mapOf("hcPartyId" to listOf("$hcPartyId"), "secretFKeys" to listOf("$secretFKeys"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/byHcPartySecretForeignKeys", query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List helement stubs found By Healthcare Party and secret foreign keys.
     * Keys must be delimited by coma
     * @param hcPartyId  
     * @param secretFKeys  
     * @return kotlin.Array<IcureStubDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun findInvoicesDelegationsStubsByHCPartyPatientForeignKeys(hcPartyId: kotlin.String, secretFKeys: kotlin.String): kotlin.Array<IcureStubDto> {
        val localVariableQuery: MultiValueMap = mapOf("hcPartyId" to listOf("$hcPartyId"), "secretFKeys" to listOf("$secretFKeys"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/byHcPartySecretForeignKeys/delegations", query = localVariableQuery
        )
        val response = request<kotlin.Array<IcureStubDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<IcureStubDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets an invoice
     * 
     * @param invoiceId  
     * @return InvoiceDto
     */
    @Suppress("UNCHECKED_CAST")
    fun getInvoice(invoiceId: kotlin.String): InvoiceDto {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/{invoiceId}".replace("{" + "invoiceId" + "}", "$invoiceId")
        )
        val response = request<InvoiceDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as InvoiceDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets an invoice
     * 
     * @param body  
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun getInvoices(body: ListOfIdsDto): kotlin.Array<InvoiceDto> {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/byIds"
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get the list of all used tarifications frequencies in invoices
     * 
     * @param minOccurences  
     * @return kotlin.Array<LabelledOccurenceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun getTarificationsCodesOccurences(minOccurences: kotlin.Long): kotlin.Array<LabelledOccurenceDto> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/codes/{minOccurences}".replace("{" + "minOccurences" + "}", "$minOccurences")
        )
        val response = request<kotlin.Array<LabelledOccurenceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<LabelledOccurenceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices per status
     * 
     * @param body  
     * @param status  
     * @param from  (optional)
     * @param to  (optional)
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listAllHcpsByStatus(body: ListOfIdsDto, status: kotlin.String, from: kotlin.Long? = null, to: kotlin.Long? = null): kotlin.Array<InvoiceDto> {
        val localVariableBody: kotlin.Any? = body
        val localVariableQuery: MultiValueMap = mapOf("from" to listOf("$from"), "to" to listOf("$to"))
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/allHcpsByStatus/{status}".replace("{" + "status" + "}", "$status"), query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param body  
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listByContactIds(body: ListOfIdsDto): kotlin.Array<InvoiceDto> {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/byCtcts"
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List invoices by groupId
     * Keys have to delimited by coma
     * @param hcPartyId  
     * @param groupId  
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listByHcPartyGroupId(hcPartyId: kotlin.String, groupId: kotlin.String): kotlin.Array<InvoiceDto> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/byHcPartyGroupId/{hcPartyId}/{groupId}".replace("{" + "hcPartyId" + "}", "$hcPartyId").replace("{" + "groupId" + "}", "$groupId")
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * List invoices by type, sent or unsent
     * Keys have to delimited by coma
     * @param hcPartyId  
     * @param sentMediumType  
     * @param invoiceType  
     * @param sent  
     * @param from  (optional)
     * @param to  (optional)
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listByHcPartySentMediumTypeInvoiceTypeSentDate(hcPartyId: kotlin.String, sentMediumType: kotlin.String, invoiceType: kotlin.String, sent: kotlin.Boolean, from: kotlin.Long? = null, to: kotlin.Long? = null): kotlin.Array<InvoiceDto> {
        val localVariableQuery: MultiValueMap = mapOf("from" to listOf("$from"), "to" to listOf("$to"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/byHcParty/{hcPartyId}/mediumType/{sentMediumType}/invoiceType/{invoiceType}/sent/{sent}".replace("{" + "hcPartyId" + "}", "$hcPartyId").replace("{" + "sentMediumType" + "}", "$sentMediumType").replace("{" + "invoiceType" + "}", "$invoiceType").replace("{" + "sent" + "}", "$sent"), query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Get all invoices by author, by sending mode, by status and by date
     * 
     * @param hcPartyId  
     * @param sendingMode  (optional)
     * @param status  (optional)
     * @param from  (optional)
     * @param to  (optional)
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listByHcpartySendingModeStatusDate(hcPartyId: kotlin.String, sendingMode: kotlin.String? = null, status: kotlin.String? = null, from: kotlin.Long? = null, to: kotlin.Long? = null): kotlin.Array<InvoiceDto> {
        val localVariableQuery: MultiValueMap = mapOf("sendingMode" to listOf("$sendingMode"), "status" to listOf("$status"), "from" to listOf("$from"), "to" to listOf("$to"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/byHcpartySendingModeStatusDate/{hcPartyId}".replace("{" + "hcPartyId" + "}", "$hcPartyId"), query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param invoiceIds  
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listByIds(invoiceIds: kotlin.String): kotlin.Array<InvoiceDto> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/byIds/{invoiceIds}".replace("{" + "invoiceIds" + "}", "$invoiceIds")
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param recipientIds  
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listByRecipientsIds(recipientIds: kotlin.String): kotlin.Array<InvoiceDto> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/to/{recipientIds}".replace("{" + "recipientIds" + "}", "$recipientIds")
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param serviceIds  
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listByServiceIds(serviceIds: kotlin.String): kotlin.Array<InvoiceDto> {
        
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/byServiceIds/{serviceIds}".replace("{" + "serviceIds" + "}", "$serviceIds")
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param userIds  (optional)
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listToInsurances(userIds: kotlin.String? = null): kotlin.Array<InvoiceDto> {
        val localVariableQuery: MultiValueMap = mapOf("userIds" to listOf("$userIds"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/toInsurances", query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param userIds  (optional)
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listToInsurancesUnsent(userIds: kotlin.String? = null): kotlin.Array<InvoiceDto> {
        val localVariableQuery: MultiValueMap = mapOf("userIds" to listOf("$userIds"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/toInsurances/unsent", query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param hcPartyId  (optional)
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listToPatients(hcPartyId: kotlin.String? = null): kotlin.Array<InvoiceDto> {
        val localVariableQuery: MultiValueMap = mapOf("hcPartyId" to listOf("$hcPartyId"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/toPatients", query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param hcPartyId  (optional)
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun listToPatientsUnsent(hcPartyId: kotlin.String? = null): kotlin.Array<InvoiceDto> {
        val localVariableQuery: MultiValueMap = mapOf("hcPartyId" to listOf("$hcPartyId"))
        val localVariableConfig = RequestConfig(
                RequestMethod.GET,
                "/rest/v1/invoice/toPatients/unsent", query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param body  
     * @param invoiceId  
     * @return InvoiceDto
     */
    @Suppress("UNCHECKED_CAST")
    fun mergeTo(body: ListOfIdsDto, invoiceId: kotlin.String): InvoiceDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/mergeTo/{invoiceId}".replace("{" + "invoiceId" + "}", "$invoiceId")
        )
        val response = request<InvoiceDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as InvoiceDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Modifies an invoice
     * 
     * @param body  
     * @return InvoiceDto
     */
    @Suppress("UNCHECKED_CAST")
    fun modifyInvoice(body: InvoiceDto): InvoiceDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.PUT,
                "/rest/v1/invoice"
        )
        val response = request<InvoiceDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as InvoiceDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Adds a delegation to a invoice
     * 
     * @param body  
     * @param invoiceId  
     * @return InvoiceDto
     */
    @Suppress("UNCHECKED_CAST")
    fun newInvoiceDelegations(body: kotlin.Array<DelegationDto>, invoiceId: kotlin.String): InvoiceDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.PUT,
                "/rest/v1/invoice/{invoiceId}/delegate".replace("{" + "invoiceId" + "}", "$invoiceId")
        )
        val response = request<InvoiceDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as InvoiceDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Modifies an invoice
     * 
     * @param body  
     * @return InvoiceDto
     */
    @Suppress("UNCHECKED_CAST")
    fun reassignInvoice(body: InvoiceDto): InvoiceDto {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/reassign"
        )
        val response = request<InvoiceDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as InvoiceDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param body  
     * @param secretFKeys  
     * @param userId  
     * @param serviceId  
     * @return kotlin.Array<InvoiceDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun removeCodes(body: kotlin.Array<kotlin.String>, secretFKeys: kotlin.String, userId: kotlin.String, serviceId: kotlin.String): kotlin.Array<InvoiceDto> {
        val localVariableBody: kotlin.Any? = body
        val localVariableQuery: MultiValueMap = mapOf("secretFKeys" to listOf("$secretFKeys"))
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/byauthor/{userId}/service/{serviceId}".replace("{" + "userId" + "}", "$userId").replace("{" + "serviceId" + "}", "$serviceId"), query = localVariableQuery
        )
        val response = request<kotlin.Array<InvoiceDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<InvoiceDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Update delegations in healthElements.
     * Keys must be delimited by coma
     * @param body  
     * @return kotlin.Array<IcureStubDto>
     */
    @Suppress("UNCHECKED_CAST")
    fun setInvoicesDelegations(body: kotlin.Array<IcureStubDto>): kotlin.Array<IcureStubDto> {
        val localVariableBody: kotlin.Any? = body
        
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/delegations"
        )
        val response = request<kotlin.Array<IcureStubDto>>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as kotlin.Array<IcureStubDto>
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
    /**
     * Gets all invoices for author at date
     * 
     * @param invoiceId  
     * @param scheme  
     * @param forcedValue  
     * @return InvoiceDto
     */
    @Suppress("UNCHECKED_CAST")
    fun validate(invoiceId: kotlin.String, scheme: kotlin.String, forcedValue: kotlin.String): InvoiceDto {
        val localVariableQuery: MultiValueMap = mapOf("scheme" to listOf("$scheme"), "forcedValue" to listOf("$forcedValue"))
        val localVariableConfig = RequestConfig(
                RequestMethod.POST,
                "/rest/v1/invoice/validate/{invoiceId}".replace("{" + "invoiceId" + "}", "$invoiceId"), query = localVariableQuery
        )
        val response = request<InvoiceDto>(
                localVariableConfig
        )

        return when (response.responseType) {
            ResponseType.Success -> (response as Success<*>).data as InvoiceDto
            ResponseType.Informational -> TODO()
            ResponseType.Redirection -> TODO()
            ResponseType.ClientError -> throw ClientException((response as ClientError<*>).body as? String ?: "Client error")
            ResponseType.ServerError -> throw ServerException((response as ServerError<*>).message ?: "Server error")
        }
    }
}
