
# PartnershipDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**type** | [**inline**](#TypeEnum) | Type of relationship. |  [optional]
**status** | [**inline**](#StatusEnum) | Status of the relationship. |  [optional]
**partnerId** | **kotlin.String** | UUID of the contact person or patient in this relationship. |  [optional]
**meToOtherRelationshipDescription** | **kotlin.String** |  |  [optional]
**otherToMeRelationshipDescription** | **kotlin.String** |  |  [optional]


<a name="TypeEnum"></a>
## Enum: type
Name | Value
---- | -----
type | primary_contact, primary_contact_for, family, friend, counselor, contact, brother, brotherinlaw, child, daughter, employer, father, grandchild, grandparent, husband, lawyer, mother, neighbour, notary, partner, sister, sisterinlaw, son, spouse, stepdaughter, stepfather, stepmother, stepson, tutor, next_of_kin, federal_agency, insurance_company, state_agency, unknown


<a name="StatusEnum"></a>
## Enum: status
Name | Value
---- | -----
status | active, complicated, past



