/**
 * iCure Cloud API Documentation
 *
 * Spring shop sample application
 *
 * The version of the OpenAPI document: v0.0.1
 * 
 *
 * Please note:
 * This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * Do not edit this file manually.
 */
package io.icure.kraken.client.apis

import io.icure.asyncjacksonhttpclient.net.web.WebClient
import io.icure.asyncjacksonhttpclient.netty.NettyWebClient
import io.icure.kraken.client.models.AppointmentDto
import io.icure.kraken.client.models.AppointmentImportDto
import io.icure.kraken.client.models.EmailOrSmsMessageDto
import io.icure.kraken.client.models.MikronoAppointmentTypeRestDto
import io.icure.kraken.client.models.MikronoCredentialsDto
import io.icure.kraken.client.models.UserDto


import io.icure.kraken.client.infrastructure.ApiClient
import io.icure.kraken.client.infrastructure.ClientException
import io.icure.kraken.client.infrastructure.ServerException
import io.icure.kraken.client.infrastructure.MultiValueMap
import io.icure.kraken.client.infrastructure.RequestConfig
import io.icure.kraken.client.infrastructure.RequestMethod
import javax.inject.Named

@Named
@ExperimentalStdlibApi
@ExperimentalCoroutinesApi
class BemikronoApi(basePath: kotlin.String = defaultBasePath, webClient: WebClient = NettyWebClient(), authHeader: String? = null) : ApiClient(basePath, webClient, authHeader) {
    companion object {
        @JvmStatic
        val defaultBasePath: String by lazy {
            System.getProperties().getProperty("io.icure.kraken.client.baseUrl", "https://kraken.icure.dev")
        }
    }

    /**
    * Get appointments for patient
    * 
    * @param calendarDate  
    * @return kotlin.collections.List<AppointmentDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    fun appointmentsByDate(calendarDate: kotlin.Long) : kotlin.collections.List<AppointmentDto>? {
        val localVariableConfig = appointmentsByDateRequestConfig(calendarDate = calendarDate)

        return request<Unit, kotlin.collections.List<AppointmentDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation appointmentsByDate
    *
    * @param calendarDate  
    * @return RequestConfig
    */
    fun appointmentsByDateRequestConfig(calendarDate: kotlin.Long) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/be_mikrono/appointments/byDate/{calendarDate}".replace("{"+"calendarDate"+"}", "$calendarDate"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Get appointments for patient
    * 
    * @param patientId  
    * @param from  (optional)
    * @param to  (optional)
    * @return kotlin.collections.List<AppointmentDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    fun appointmentsByPatient(patientId: kotlin.String, from: kotlin.Long?, to: kotlin.Long?) : kotlin.collections.List<AppointmentDto>? {
        val localVariableConfig = appointmentsByPatientRequestConfig(patientId = patientId, from = from, to = to)

        return request<Unit, kotlin.collections.List<AppointmentDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation appointmentsByPatient
    *
    * @param patientId  
    * @param from  (optional)
    * @param to  (optional)
    * @return RequestConfig
    */
    fun appointmentsByPatientRequestConfig(patientId: kotlin.String, from: kotlin.Long?, to: kotlin.Long?) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf<kotlin.String, List<kotlin.String>>()
            .apply {
                if (from != null) {
                    put("from", listOf(from.toString()))
                }
                if (to != null) {
                    put("to", listOf(to.toString()))
                }
            }
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/be_mikrono/appointments/byPatient/{patientId}".replace("{"+"patientId"+"}", "$patientId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * 
    * 
    * @param mikronoAppointmentTypeRestDto  (optional)
    * @return kotlin.collections.List<MikronoAppointmentTypeRestDto>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    fun createAppointmentTypes(mikronoAppointmentTypeRestDto: kotlin.collections.List<MikronoAppointmentTypeRestDto>?) : kotlin.collections.List<MikronoAppointmentTypeRestDto>? {
        val localVariableConfig = createAppointmentTypesRequestConfig(mikronoAppointmentTypeRestDto = mikronoAppointmentTypeRestDto)

        return request<kotlin.collections.List<MikronoAppointmentTypeRestDto>, kotlin.collections.List<MikronoAppointmentTypeRestDto>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createAppointmentTypes
    *
    * @param mikronoAppointmentTypeRestDto  (optional)
    * @return RequestConfig
    */
    fun createAppointmentTypesRequestConfig(mikronoAppointmentTypeRestDto: kotlin.collections.List<MikronoAppointmentTypeRestDto>?) : RequestConfig<kotlin.collections.List<MikronoAppointmentTypeRestDto>> {
        val localVariableBody = mikronoAppointmentTypeRestDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/be_mikrono/appointmentTypes",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Create appointments for owner
    * 
    * @param appointmentImportDto  
    * @return kotlin.collections.List<kotlin.String>
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    fun createAppointments(appointmentImportDto: kotlin.collections.List<AppointmentImportDto>) : kotlin.collections.List<kotlin.String>? {
        val localVariableConfig = createAppointmentsRequestConfig(appointmentImportDto = appointmentImportDto)

        return request<kotlin.collections.List<AppointmentImportDto>, kotlin.collections.List<kotlin.String>>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation createAppointments
    *
    * @param appointmentImportDto  
    * @return RequestConfig
    */
    fun createAppointmentsRequestConfig(appointmentImportDto: kotlin.collections.List<AppointmentImportDto>) : RequestConfig<kotlin.collections.List<AppointmentImportDto>> {
        val localVariableBody = appointmentImportDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/be_mikrono/appointments",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Notify of an appointment change
    * 
    * @param appointmentId  
    * @param action  
    * @return void
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    fun notify(appointmentId: kotlin.String, action: kotlin.String) : Unit? {
        val localVariableConfig = notifyRequestConfig(appointmentId = appointmentId, action = action)

        return request<Unit, Unit>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation notify
    *
    * @param appointmentId  
    * @param action  
    * @return RequestConfig
    */
    fun notifyRequestConfig(appointmentId: kotlin.String, action: kotlin.String) : RequestConfig<Unit> {
        val localVariableBody = null
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.GET,
            path = "/rest/v1/be_mikrono/notify/{appointmentId}/{action}".replace("{"+"appointmentId"+"}", "$appointmentId").replace("{"+"action"+"}", "$action"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Set credentials for provided user
    * 
    * @param userId  
    * @param mikronoCredentialsDto  
    * @return UserDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    fun register(userId: kotlin.String, mikronoCredentialsDto: MikronoCredentialsDto) : UserDto? {
        val localVariableConfig = registerRequestConfig(userId = userId, mikronoCredentialsDto = mikronoCredentialsDto)

        return request<MikronoCredentialsDto, UserDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation register
    *
    * @param userId  
    * @param mikronoCredentialsDto  
    * @return RequestConfig
    */
    fun registerRequestConfig(userId: kotlin.String, mikronoCredentialsDto: MikronoCredentialsDto) : RequestConfig<MikronoCredentialsDto> {
        val localVariableBody = mikronoCredentialsDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/be_mikrono/user/{userId}/register".replace("{"+"userId"+"}", "$userId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Send message using mikrono from logged user
    * 
    * @param emailOrSmsMessageDto  
    * @return kotlin.Any
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    fun sendMessage(emailOrSmsMessageDto: EmailOrSmsMessageDto) : kotlin.Any? {
        val localVariableConfig = sendMessageRequestConfig(emailOrSmsMessageDto = emailOrSmsMessageDto)

        return request<EmailOrSmsMessageDto, kotlin.Any>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation sendMessage
    *
    * @param emailOrSmsMessageDto  
    * @return RequestConfig
    */
    fun sendMessageRequestConfig(emailOrSmsMessageDto: EmailOrSmsMessageDto) : RequestConfig<EmailOrSmsMessageDto> {
        val localVariableBody = emailOrSmsMessageDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.POST,
            path = "/rest/v1/be_mikrono/sendMessage",
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

    /**
    * Set credentials for provided user
    * 
    * @param userId  
    * @param mikronoCredentialsDto  (optional)
    * @return UserDto
    * @throws UnsupportedOperationException If the API returns an informational or redirection response
    * @throws ClientException If the API returns a client error response
    * @throws ServerException If the API returns a server error response
    */
    @Suppress("UNCHECKED_CAST")
    @Throws(UnsupportedOperationException::class, ClientException::class, ServerException::class)
    fun setUserCredentials(userId: kotlin.String, mikronoCredentialsDto: MikronoCredentialsDto?) : UserDto? {
        val localVariableConfig = setUserCredentialsRequestConfig(userId = userId, mikronoCredentialsDto = mikronoCredentialsDto)

        return request<MikronoCredentialsDto, UserDto>(
            localVariableConfig
        )
    }

    /**
    * To obtain the request config of the operation setUserCredentials
    *
    * @param userId  
    * @param mikronoCredentialsDto  (optional)
    * @return RequestConfig
    */
    fun setUserCredentialsRequestConfig(userId: kotlin.String, mikronoCredentialsDto: MikronoCredentialsDto?) : RequestConfig<MikronoCredentialsDto> {
        val localVariableBody = mikronoCredentialsDto
        val localVariableQuery: MultiValueMap = mutableMapOf()
        val localVariableHeaders: MutableMap<String, String> = mutableMapOf()

        return RequestConfig(
            method = RequestMethod.PUT,
            path = "/rest/v1/be_mikrono/user/{userId}/credentials".replace("{"+"userId"+"}", "$userId"),
            query = localVariableQuery,
            headers = localVariableHeaders,
            body = localVariableBody
        )
    }

}
