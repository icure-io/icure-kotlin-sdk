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
import com.github.pozo.KotlinBuilder


/**
 * Time periods
 *
 * @param startDate The date (unix epoch in ms) when the referral period initiated, will be filled instantaneously.
 * @param endDate The date (unix epoch in ms) the referral period ended, will be instantaneously filled.
 * @param comment Comments made during the referral.
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class ReferralPeriodDto (

    /* The date (unix epoch in ms) when the referral period initiated, will be filled instantaneously. */
    @field:JsonProperty("startDate")
    val startDate: java.time.OffsetDateTime? = null,

    /* The date (unix epoch in ms) the referral period ended, will be instantaneously filled. */
    @field:JsonProperty("endDate")
    val endDate: java.time.OffsetDateTime? = null,

    /* Comments made during the referral. */
    @field:JsonProperty("comment")
    val comment: kotlin.String? = null

)

