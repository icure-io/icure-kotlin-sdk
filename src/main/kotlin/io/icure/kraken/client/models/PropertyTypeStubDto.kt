/**
 * iCure Data Stack API Documentation
 *
 * The iCure Data Stack Application API is the native interface to iCure.
 *
 * The version of the OpenAPI document: v2
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
 * 
 *
 * @param identifier 
 * @param type 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class PropertyTypeStubDto (

    @field:JsonProperty("identifier")
    val identifier: kotlin.String? = null,

    @field:JsonProperty("type")
    val type: PropertyTypeStubDto.Type? = null

) {

    /**
     * 
     *
     * Values: bOOLEAN,iNTEGER,dOUBLE,sTRING,dATE,cLOB,jSON
     */
    enum class Type(val value: kotlin.String) {
        @JsonProperty(value = "BOOLEAN") bOOLEAN("BOOLEAN"),
        @JsonProperty(value = "INTEGER") iNTEGER("INTEGER"),
        @JsonProperty(value = "DOUBLE") dOUBLE("DOUBLE"),
        @JsonProperty(value = "STRING") sTRING("STRING"),
        @JsonProperty(value = "DATE") dATE("DATE"),
        @JsonProperty(value = "CLOB") cLOB("CLOB"),
        @JsonProperty(value = "JSON") jSON("JSON");
    }
}

