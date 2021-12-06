
# PersonNameDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**firstNames** | **kotlin.collections.List&lt;kotlin.String&gt;** | Given names (not always &#39;first&#39;). Includes middle names. This repeating element order: Given Names appear in the correct order for presenting the name | 
**prefix** | **kotlin.collections.List&lt;kotlin.String&gt;** | Parts that come before the name. This repeating element order: Prefixes appear in the correct order for presenting the name | 
**suffix** | **kotlin.collections.List&lt;kotlin.String&gt;** | Parts that come after the name. This repeating element order: Suffixes appear in the correct order for presenting the name | 
**lastName** | **kotlin.String** | Family name (often called &#39;Surname&#39;) |  [optional]
**start** | **kotlin.Long** | Starting date of time period when name is/was valid for use. Date encoded as a fuzzy date on 8 positions (YYYYMMDD) |  [optional]
**end** | **kotlin.Long** | Ending date of time period when name is/was valid for use. Date encoded as a fuzzy date on 8 positions (YYYYMMDD) |  [optional]
**text** | **kotlin.String** | Text representation of the full name |  [optional]
**use** | [**inline**](#UseEnum) | What is the use of this name |  [optional]


<a name="UseEnum"></a>
## Enum: use
Name | Value
---- | -----
use | usual, official, temp, nickname, anonymous, maiden, old, other



