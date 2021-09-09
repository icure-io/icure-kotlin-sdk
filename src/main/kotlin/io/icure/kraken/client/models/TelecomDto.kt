/**
 * iCure Data Stack API Documentation
 *
 * The iCure Data Stack Application API is the native interface to iCure. This version is obsolete, please use v2.
 *
 * The version of the OpenAPI document: v1
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
import com.github.pozo.KotlinBuilder


/**
 * This entity represents available contact details of a user, reachable by telecom methods
 *
 * @param telecomType The type of telecom method being used, ex: landline phone, mobile phone, email, fax, etc.
 * @param telecomNumber 
 * @param telecomDescription 
 * @param encryptedSelf The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class TelecomDto (

    /* The type of telecom method being used, ex: landline phone, mobile phone, email, fax, etc. */
    @field:JsonProperty("telecomType")
    val telecomType: TelecomDto.TelecomType? = null,

    @field:JsonProperty("telecomNumber")
    val telecomNumber: kotlin.String? = null,

    @field:JsonProperty("telecomDescription")
    val telecomDescription: kotlin.String? = null,

    /* The base64 encoded data of this object, formatted as JSON and encrypted in AES using the random master key from encryptionKeys. */
    @field:JsonProperty("encryptedSelf")
    val encryptedSelf: kotlin.String? = null

) {

    /**
     * The type of telecom method being used, ex: landline phone, mobile phone, email, fax, etc.
     *
     * Values: mobile,phone,email,fax,skype,im,medibridge,ehealthbox,apicrypt,web,print,disk,other
     */
    enum class TelecomType(val value: kotlin.String) {
        @JsonProperty(value = "mobile") mobile("mobile"),
        @JsonProperty(value = "phone") phone("phone"),
        @JsonProperty(value = "email") email("email"),
        @JsonProperty(value = "fax") fax("fax"),
        @JsonProperty(value = "skype") skype("skype"),
        @JsonProperty(value = "im") im("im"),
        @JsonProperty(value = "medibridge") medibridge("medibridge"),
        @JsonProperty(value = "ehealthbox") ehealthbox("ehealthbox"),
        @JsonProperty(value = "apicrypt") apicrypt("apicrypt"),
        @JsonProperty(value = "web") web("web"),
        @JsonProperty(value = "print") print("print"),
        @JsonProperty(value = "disk") disk("disk"),
        @JsonProperty(value = "other") other("other");
    }
}

