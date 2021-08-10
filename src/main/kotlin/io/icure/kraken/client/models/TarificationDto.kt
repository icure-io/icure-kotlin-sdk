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

import io.icure.kraken.client.models.LetterValueDto
import io.icure.kraken.client.models.PeriodicityDto
import io.icure.kraken.client.models.ValorisationDto

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude


/**
 * 
 *
 * @param id 
 * @param regions 
 * @param periodicity 
 * @param links 
 * @param qualifiedLinks 
 * @param flags 
 * @param searchTerms 
 * @param appendices 
 * @param disabled 
 * @param valorisations 
 * @param category 
 * @param relatedCodes 
 * @param letterValues 
 * @param rev 
 * @param deletionDate hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called.
 * @param label 
 * @param context 
 * @param type 
 * @param code 
 * @param version 
 * @param author 
 * @param level 
 * @param data 
 * @param consultationCode 
 * @param hasRelatedCode 
 * @param needsPrescriber 
 * @param nGroup 
 * @param ngroup 
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class TarificationDto (

    @field:JsonProperty("id")
    val id: kotlin.String,

    @field:JsonProperty("regions")
    val regions: kotlin.collections.List<kotlin.String>,

    @field:JsonProperty("periodicity")
    val periodicity: kotlin.collections.List<PeriodicityDto>,

    @field:JsonProperty("links")
    val links: kotlin.collections.List<kotlin.String>,

    @field:JsonProperty("qualifiedLinks")
    val qualifiedLinks: kotlin.collections.Map<kotlin.String, kotlin.collections.List<kotlin.String>>,

    @field:JsonProperty("flags")
    val flags: kotlin.collections.List<TarificationDto.Flags>,

    @field:JsonProperty("searchTerms")
    val searchTerms: kotlin.collections.Map<kotlin.String, kotlin.collections.Set<kotlin.String>>,

    @field:JsonProperty("appendices")
    val appendices: kotlin.collections.Map<kotlin.String, kotlin.String>,

    @field:JsonProperty("disabled")
    val disabled: kotlin.Boolean,

    @field:JsonProperty("valorisations")
    val valorisations: kotlin.collections.List<ValorisationDto>,

    @field:JsonProperty("category")
    val category: kotlin.collections.Map<kotlin.String, kotlin.String>,

    @field:JsonProperty("relatedCodes")
    val relatedCodes: kotlin.collections.List<kotlin.String>,

    @field:JsonProperty("letterValues")
    val letterValues: kotlin.collections.List<LetterValueDto>,

    @field:JsonProperty("rev")
    val rev: kotlin.String? = null,

    /* hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. */
    @field:JsonProperty("deletionDate")
    val deletionDate: kotlin.Long? = null,

    @field:JsonProperty("label")
    val label: kotlin.collections.Map<kotlin.String, kotlin.String>? = null,

    @field:JsonProperty("context")
    val context: kotlin.String? = null,

    @field:JsonProperty("type")
    val type: kotlin.String? = null,

    @field:JsonProperty("code")
    val code: kotlin.String? = null,

    @field:JsonProperty("version")
    val version: kotlin.String? = null,

    @field:JsonProperty("author")
    val author: kotlin.String? = null,

    @field:JsonProperty("level")
    val level: kotlin.Int? = null,

    @field:JsonProperty("data")
    val data: kotlin.String? = null,

    @field:JsonProperty("consultationCode")
    val consultationCode: kotlin.Boolean? = null,

    @field:JsonProperty("hasRelatedCode")
    val hasRelatedCode: kotlin.Boolean? = null,

    @field:JsonProperty("needsPrescriber")
    val needsPrescriber: kotlin.Boolean? = null,

    @field:JsonProperty("nGroup")
    val nGroup: kotlin.String? = null,

    @field:JsonProperty("ngroup")
    val ngroup: kotlin.String? = null

) {

    /**
     * 
     *
     * Values: maleOnly,femaleOnly,deptkinesitherapy,deptnursing,deptgeneralpractice,deptsocialworker,deptpsychology,deptadministrative,deptdietetics,deptspeechtherapy,deptdentistry,deptoccupationaltherapy,depthealthcare,deptgynecology,deptpediatry,deptalgology,deptanatomopathology,deptanesthesiology,deptbacteriology,deptcardiacsurgery,deptcardiology,deptchildandadolescentpsychiatry,deptdermatology,deptdiabetology,deptemergency,deptendocrinology,deptgastroenterology,deptgenetics,deptgeriatry,depthandsurgery,depthematology,deptinfectiousdisease,deptintensivecare,deptlaboratory,deptmajorburns,deptmaxillofacialsurgery,deptmedicine,deptmolecularbiology,deptneonatalogy,deptnephrology,deptneurology,deptneurosurgery,deptnte,deptnuclear,deptnutritiondietetics,deptobstetrics,deptoncology,deptophtalmology,deptorthopedy,deptpalliativecare,deptpediatricintensivecare,deptpediatricsurgery,deptpharmacy,deptphysicalmedecine,deptphysiotherapy,deptplasticandreparatorysurgery,deptpneumology,deptpodiatry,deptpsychiatry,deptradiology,deptradiotherapy,deptrevalidation,deptrheumatology,deptrhumatology,deptsenology,deptsocialservice,deptsportsmedecine,deptstomatology,deptsurgery,deptthoracicsurgery,depttoxicology,depttropicalmedecine,depturology,deptvascularsurgery,deptvisceraldigestiveabdominalsurgery,depttransplantsurgery,deptpercutaneous,deptchildbirth
     */
    enum class Flags(val value: kotlin.String) {
        @JsonProperty(value = "male_only") maleOnly("male_only"),
        @JsonProperty(value = "female_only") femaleOnly("female_only"),
        @JsonProperty(value = "deptkinesitherapy") deptkinesitherapy("deptkinesitherapy"),
        @JsonProperty(value = "deptnursing") deptnursing("deptnursing"),
        @JsonProperty(value = "deptgeneralpractice") deptgeneralpractice("deptgeneralpractice"),
        @JsonProperty(value = "deptsocialworker") deptsocialworker("deptsocialworker"),
        @JsonProperty(value = "deptpsychology") deptpsychology("deptpsychology"),
        @JsonProperty(value = "deptadministrative") deptadministrative("deptadministrative"),
        @JsonProperty(value = "deptdietetics") deptdietetics("deptdietetics"),
        @JsonProperty(value = "deptspeechtherapy") deptspeechtherapy("deptspeechtherapy"),
        @JsonProperty(value = "deptdentistry") deptdentistry("deptdentistry"),
        @JsonProperty(value = "deptoccupationaltherapy") deptoccupationaltherapy("deptoccupationaltherapy"),
        @JsonProperty(value = "depthealthcare") depthealthcare("depthealthcare"),
        @JsonProperty(value = "deptgynecology") deptgynecology("deptgynecology"),
        @JsonProperty(value = "deptpediatry") deptpediatry("deptpediatry"),
        @JsonProperty(value = "deptalgology") deptalgology("deptalgology"),
        @JsonProperty(value = "deptanatomopathology") deptanatomopathology("deptanatomopathology"),
        @JsonProperty(value = "deptanesthesiology") deptanesthesiology("deptanesthesiology"),
        @JsonProperty(value = "deptbacteriology") deptbacteriology("deptbacteriology"),
        @JsonProperty(value = "deptcardiacsurgery") deptcardiacsurgery("deptcardiacsurgery"),
        @JsonProperty(value = "deptcardiology") deptcardiology("deptcardiology"),
        @JsonProperty(value = "deptchildandadolescentpsychiatry") deptchildandadolescentpsychiatry("deptchildandadolescentpsychiatry"),
        @JsonProperty(value = "deptdermatology") deptdermatology("deptdermatology"),
        @JsonProperty(value = "deptdiabetology") deptdiabetology("deptdiabetology"),
        @JsonProperty(value = "deptemergency") deptemergency("deptemergency"),
        @JsonProperty(value = "deptendocrinology") deptendocrinology("deptendocrinology"),
        @JsonProperty(value = "deptgastroenterology") deptgastroenterology("deptgastroenterology"),
        @JsonProperty(value = "deptgenetics") deptgenetics("deptgenetics"),
        @JsonProperty(value = "deptgeriatry") deptgeriatry("deptgeriatry"),
        @JsonProperty(value = "depthandsurgery") depthandsurgery("depthandsurgery"),
        @JsonProperty(value = "depthematology") depthematology("depthematology"),
        @JsonProperty(value = "deptinfectiousdisease") deptinfectiousdisease("deptinfectiousdisease"),
        @JsonProperty(value = "deptintensivecare") deptintensivecare("deptintensivecare"),
        @JsonProperty(value = "deptlaboratory") deptlaboratory("deptlaboratory"),
        @JsonProperty(value = "deptmajorburns") deptmajorburns("deptmajorburns"),
        @JsonProperty(value = "deptmaxillofacialsurgery") deptmaxillofacialsurgery("deptmaxillofacialsurgery"),
        @JsonProperty(value = "deptmedicine") deptmedicine("deptmedicine"),
        @JsonProperty(value = "deptmolecularbiology") deptmolecularbiology("deptmolecularbiology"),
        @JsonProperty(value = "deptneonatalogy") deptneonatalogy("deptneonatalogy"),
        @JsonProperty(value = "deptnephrology") deptnephrology("deptnephrology"),
        @JsonProperty(value = "deptneurology") deptneurology("deptneurology"),
        @JsonProperty(value = "deptneurosurgery") deptneurosurgery("deptneurosurgery"),
        @JsonProperty(value = "deptnte") deptnte("deptnte"),
        @JsonProperty(value = "deptnuclear") deptnuclear("deptnuclear"),
        @JsonProperty(value = "deptnutritiondietetics") deptnutritiondietetics("deptnutritiondietetics"),
        @JsonProperty(value = "deptobstetrics") deptobstetrics("deptobstetrics"),
        @JsonProperty(value = "deptoncology") deptoncology("deptoncology"),
        @JsonProperty(value = "deptophtalmology") deptophtalmology("deptophtalmology"),
        @JsonProperty(value = "deptorthopedy") deptorthopedy("deptorthopedy"),
        @JsonProperty(value = "deptpalliativecare") deptpalliativecare("deptpalliativecare"),
        @JsonProperty(value = "deptpediatricintensivecare") deptpediatricintensivecare("deptpediatricintensivecare"),
        @JsonProperty(value = "deptpediatricsurgery") deptpediatricsurgery("deptpediatricsurgery"),
        @JsonProperty(value = "deptpharmacy") deptpharmacy("deptpharmacy"),
        @JsonProperty(value = "deptphysicalmedecine") deptphysicalmedecine("deptphysicalmedecine"),
        @JsonProperty(value = "deptphysiotherapy") deptphysiotherapy("deptphysiotherapy"),
        @JsonProperty(value = "deptplasticandreparatorysurgery") deptplasticandreparatorysurgery("deptplasticandreparatorysurgery"),
        @JsonProperty(value = "deptpneumology") deptpneumology("deptpneumology"),
        @JsonProperty(value = "deptpodiatry") deptpodiatry("deptpodiatry"),
        @JsonProperty(value = "deptpsychiatry") deptpsychiatry("deptpsychiatry"),
        @JsonProperty(value = "deptradiology") deptradiology("deptradiology"),
        @JsonProperty(value = "deptradiotherapy") deptradiotherapy("deptradiotherapy"),
        @JsonProperty(value = "deptrevalidation") deptrevalidation("deptrevalidation"),
        @JsonProperty(value = "deptrheumatology") deptrheumatology("deptrheumatology"),
        @JsonProperty(value = "deptrhumatology") deptrhumatology("deptrhumatology"),
        @JsonProperty(value = "deptsenology") deptsenology("deptsenology"),
        @JsonProperty(value = "deptsocialservice") deptsocialservice("deptsocialservice"),
        @JsonProperty(value = "deptsportsmedecine") deptsportsmedecine("deptsportsmedecine"),
        @JsonProperty(value = "deptstomatology") deptstomatology("deptstomatology"),
        @JsonProperty(value = "deptsurgery") deptsurgery("deptsurgery"),
        @JsonProperty(value = "deptthoracicsurgery") deptthoracicsurgery("deptthoracicsurgery"),
        @JsonProperty(value = "depttoxicology") depttoxicology("depttoxicology"),
        @JsonProperty(value = "depttropicalmedecine") depttropicalmedecine("depttropicalmedecine"),
        @JsonProperty(value = "depturology") depturology("depturology"),
        @JsonProperty(value = "deptvascularsurgery") deptvascularsurgery("deptvascularsurgery"),
        @JsonProperty(value = "deptvisceraldigestiveabdominalsurgery") deptvisceraldigestiveabdominalsurgery("deptvisceraldigestiveabdominalsurgery"),
        @JsonProperty(value = "depttransplantsurgery") depttransplantsurgery("depttransplantsurgery"),
        @JsonProperty(value = "deptpercutaneous") deptpercutaneous("deptpercutaneous"),
        @JsonProperty(value = "deptchildbirth") deptchildbirth("deptchildbirth");
    }
}

