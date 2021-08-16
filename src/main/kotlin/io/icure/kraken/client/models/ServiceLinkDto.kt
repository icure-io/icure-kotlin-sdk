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
package io.icure.kraken.client.models


import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * List of all services provided to the patient under a given contact which is linked by this sub-contact to other structuring elements.
 *
 * @param serviceId 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class ServiceLinkDto (

    @field:JsonProperty("serviceId")
    val serviceId: kotlin.String? = null

)

