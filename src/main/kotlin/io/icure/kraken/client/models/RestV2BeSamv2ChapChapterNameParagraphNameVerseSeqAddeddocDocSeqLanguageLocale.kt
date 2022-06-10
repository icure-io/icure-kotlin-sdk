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
 * @param language 
 * @param script 
 * @param country 
 * @param variant 
 * @param extensionKeys 
 * @param unicodeLocaleAttributes 
 * @param unicodeLocaleKeys 
 * @param iso3Language 
 * @param iso3Country 
 * @param displayLanguage 
 * @param displayScript 
 * @param displayCountry 
 * @param displayVariant 
 * @param displayName 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class RestV2BeSamv2ChapChapterNameParagraphNameVerseSeqAddeddocDocSeqLanguageLocale (

    @field:JsonProperty("language")
    val language: kotlin.String? = null,

    @field:JsonProperty("script")
    val script: kotlin.String? = null,

    @field:JsonProperty("country")
    val country: kotlin.String? = null,

    @field:JsonProperty("variant")
    val variant: kotlin.String? = null,

    @field:JsonProperty("extensionKeys")
    val extensionKeys: kotlin.collections.Set<kotlin.String>? = null,

    @field:JsonProperty("unicodeLocaleAttributes")
    val unicodeLocaleAttributes: kotlin.collections.Set<kotlin.String>? = null,

    @field:JsonProperty("unicodeLocaleKeys")
    val unicodeLocaleKeys: kotlin.collections.Set<kotlin.String>? = null,

    @field:JsonProperty("iso3Language")
    val iso3Language: kotlin.String? = null,

    @field:JsonProperty("iso3Country")
    val iso3Country: kotlin.String? = null,

    @field:JsonProperty("displayLanguage")
    val displayLanguage: kotlin.String? = null,

    @field:JsonProperty("displayScript")
    val displayScript: kotlin.String? = null,

    @field:JsonProperty("displayCountry")
    val displayCountry: kotlin.String? = null,

    @field:JsonProperty("displayVariant")
    val displayVariant: kotlin.String? = null,

    @field:JsonProperty("displayName")
    val displayName: kotlin.String? = null

)

