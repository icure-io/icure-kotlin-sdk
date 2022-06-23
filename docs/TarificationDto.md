
# TarificationDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** |  | 
**regions** | **kotlin.collections.Set&lt;kotlin.String&gt;** |  | 
**periodicity** | [**kotlin.collections.List&lt;PeriodicityDto&gt;**](PeriodicityDto.md) |  | 
**links** | **kotlin.collections.List&lt;kotlin.String&gt;** |  | 
**qualifiedLinks** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;kotlin.String&gt;&gt;** |  | 
**flags** | [**inline**](#kotlin.collections.Set&lt;FlagsEnum&gt;) |  | 
**searchTerms** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;kotlin.String&gt;&gt;** |  | 
**appendices** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** |  | 
**disabled** | **kotlin.Boolean** |  | 
**valorisations** | [**kotlin.collections.Set&lt;ValorisationDto&gt;**](ValorisationDto.md) |  | 
**category** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** |  | 
**relatedCodes** | **kotlin.collections.Set&lt;kotlin.String&gt;** |  | 
**letterValues** | [**kotlin.collections.List&lt;LetterValueDto&gt;**](LetterValueDto.md) |  | 
**rev** | **kotlin.String** |  |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**label** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** |  |  [optional]
**context** | **kotlin.String** |  |  [optional]
**type** | **kotlin.String** |  |  [optional]
**code** | **kotlin.String** |  |  [optional]
**version** | **kotlin.String** |  |  [optional]
**author** | **kotlin.String** |  |  [optional]
**level** | **kotlin.Int** |  |  [optional]
**&#x60;data&#x60;** | **kotlin.String** |  |  [optional]
**consultationCode** | **kotlin.Boolean** |  |  [optional]
**hasRelatedCode** | **kotlin.Boolean** |  |  [optional]
**needsPrescriber** | **kotlin.Boolean** |  |  [optional]
**nGroup** | **kotlin.String** |  |  [optional]


<a name="kotlin.collections.Set<FlagsEnum>"></a>
## Enum: flags
Name | Value
---- | -----
flags | male_only, female_only, deptkinesitherapy, deptnursing, deptgeneralpractice, deptsocialworker, deptpsychology, deptadministrative, deptdietetics, deptspeechtherapy, deptdentistry, deptoccupationaltherapy, depthealthcare, deptgynecology, deptpediatry, deptalgology, deptanatomopathology, deptanesthesiology, deptbacteriology, deptcardiacsurgery, deptcardiology, deptchildandadolescentpsychiatry, deptdermatology, deptdiabetology, deptemergency, deptendocrinology, deptgastroenterology, deptgenetics, deptgeriatry, depthandsurgery, depthematology, deptinfectiousdisease, deptintensivecare, deptlaboratory, deptmajorburns, deptmaxillofacialsurgery, deptmedicine, deptmolecularbiology, deptneonatalogy, deptnephrology, deptneurology, deptneurosurgery, deptnte, deptnuclear, deptnutritiondietetics, deptobstetrics, deptoncology, deptophtalmology, deptorthopedy, deptpalliativecare, deptpediatricintensivecare, deptpediatricsurgery, deptpharmacy, deptphysicalmedecine, deptphysiotherapy, deptplasticandreparatorysurgery, deptpneumology, deptpodiatry, deptpsychiatry, deptradiology, deptradiotherapy, deptrevalidation, deptrheumatology, deptrhumatology, deptsenology, deptsocialservice, deptsportsmedecine, deptstomatology, deptsurgery, deptthoracicsurgery, depttoxicology, depttropicalmedecine, depturology, deptvascularsurgery, deptvisceraldigestiveabdominalsurgery, depttransplantsurgery, deptpercutaneous, deptchildbirth



