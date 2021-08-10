/**
* iCure Cloud API Documentation
* Spring shop sample application
*
* The version of the OpenAPI document: v0.0.1
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
package io.icure.kraken.client.models

import io.icure.kraken.client.models.ReplicationStats

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param id 
 * @param createTarget 
 * @param continuous 
 * @param rev 
 * @param source 
 * @param target 
 * @param owner 
 * @param docIds 
 * @param replicationState 
 * @param replicationStateTime 
 * @param replicationStats 
 * @param revHistory 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class ReplicatorDocument (

    @field:JsonProperty("_id")
    val id: kotlin.String,

    @field:JsonProperty("create_target")
    val createTarget: kotlin.Boolean,

    @field:JsonProperty("continuous")
    val continuous: kotlin.Boolean,

    @field:JsonProperty("_rev")
    val rev: kotlin.String? = null,

    @field:JsonProperty("source")
    val source: kotlin.String? = null,

    @field:JsonProperty("target")
    val target: kotlin.String? = null,

    @field:JsonProperty("owner")
    val owner: kotlin.String? = null,

    @field:JsonProperty("doc_ids")
    val docIds: kotlin.collections.List<kotlin.String>? = null,

    @field:JsonProperty("_replication_state")
    val replicationState: kotlin.String? = null,

    @field:JsonProperty("_replication_state_time")
    val replicationStateTime: kotlin.String? = null,

    @field:JsonProperty("_replication_stats")
    val replicationStats: ReplicationStats? = null,

    @field:JsonProperty("rev_history")
    val revHistory: kotlin.collections.Map<kotlin.String, kotlin.String>? = null

)

