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
import com.github.pozo.KotlinBuilder


/**
 * Non preferred name information of a person
 *
 * @param firstNames Given names (not always 'first'). Includes middle names. This repeating element order: Given Names appear in the correct order for presenting the name
 * @param prefix Parts that come before the name. This repeating element order: Prefixes appear in the correct order for presenting the name
 * @param suffix Parts that come after the name. This repeating element order: Suffixes appear in the correct order for presenting the name
 * @param lastName Family name (often called 'Surname')
 * @param start Starting date of time period when name is/was valid for use. Date encoded as a fuzzy date on 8 positions (YYYYMMDD)
 * @param end Ending date of time period when name is/was valid for use. Date encoded as a fuzzy date on 8 positions (YYYYMMDD)
 * @param text Text representation of the full name
 * @param use What is the use of this name
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class PersonNameDto (

    /* Given names (not always 'first'). Includes middle names. This repeating element order: Given Names appear in the correct order for presenting the name */
    @field:JsonProperty("firstNames")
    val firstNames: kotlin.collections.List<kotlin.String> = emptyList(),

    /* Parts that come before the name. This repeating element order: Prefixes appear in the correct order for presenting the name */
    @field:JsonProperty("prefix")
    val prefix: kotlin.collections.List<kotlin.String> = emptyList(),

    /* Parts that come after the name. This repeating element order: Suffixes appear in the correct order for presenting the name */
    @field:JsonProperty("suffix")
    val suffix: kotlin.collections.List<kotlin.String> = emptyList(),

    /* Family name (often called 'Surname') */
    @field:JsonProperty("lastName")
    val lastName: kotlin.String? = null,

    /* Starting date of time period when name is/was valid for use. Date encoded as a fuzzy date on 8 positions (YYYYMMDD) */
    @field:JsonProperty("start")
    val start: kotlin.Long? = null,

    /* Ending date of time period when name is/was valid for use. Date encoded as a fuzzy date on 8 positions (YYYYMMDD) */
    @field:JsonProperty("end")
    val end: kotlin.Long? = null,

    /* Text representation of the full name */
    @field:JsonProperty("text")
    val text: kotlin.String? = null,

    /* What is the use of this name */
    @field:JsonProperty("use")
    val use: PersonNameDto.Use? = null

) {

    /**
     * What is the use of this name
     *
     * Values: usual,official,temp,nickname,anonymous,maiden,old,other
     */
    enum class Use(val value: kotlin.String) {
        @JsonProperty(value = "usual") usual("usual"),
        @JsonProperty(value = "official") official("official"),
        @JsonProperty(value = "temp") temp("temp"),
        @JsonProperty(value = "nickname") nickname("nickname"),
        @JsonProperty(value = "anonymous") anonymous("anonymous"),
        @JsonProperty(value = "maiden") maiden("maiden"),
        @JsonProperty(value = "old") old("old"),
        @JsonProperty(value = "other") other("other");
    }
}

