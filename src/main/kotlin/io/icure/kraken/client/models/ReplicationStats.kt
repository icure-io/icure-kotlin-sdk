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
 * 
 *
 * @param revisionsChecked 
 * @param missingRevisionsFound 
 * @param docsRead 
 * @param docsWritten 
 * @param changesPending 
 * @param docWriteFailures 
 * @param checkpointedSourceSeq 
 * @param startTime 
 * @param error 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class ReplicationStats (

    @field:JsonProperty("revisions_checked")
    val revisionsChecked: kotlin.Int? = null,

    @field:JsonProperty("missing_revisions_found")
    val missingRevisionsFound: kotlin.Int? = null,

    @field:JsonProperty("docs_read")
    val docsRead: kotlin.Int? = null,

    @field:JsonProperty("docs_written")
    val docsWritten: kotlin.Int? = null,

    @field:JsonProperty("changes_pending")
    val changesPending: kotlin.Int? = null,

    @field:JsonProperty("doc_write_failures")
    val docWriteFailures: kotlin.Int? = null,

    @field:JsonProperty("checkpointed_source_seq")
    val checkpointedSourceSeq: kotlin.String? = null,

    @field:JsonProperty("start_time")
    val startTime: java.time.OffsetDateTime? = null,

    @field:JsonProperty("error")
    val error: kotlin.String? = null

)

