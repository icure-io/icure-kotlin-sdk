
# UserDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** | the Id of the user. We encourage using either a v4 UUID or a HL7 Id. | 
**properties** | [**kotlin.collections.Set&lt;PropertyStubDto&gt;**](PropertyStubDto.md) | Extra properties for the user. Those properties are typed (see class Property) | 
**permissions** | [**kotlin.collections.Set&lt;PermissionDto&gt;**](PermissionDto.md) | If permission to modify patient data is granted or revoked | 
**roles** | **kotlin.collections.Set&lt;kotlin.String&gt;** | Roles specified for the user | 
**autoDelegations** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Set&lt;kotlin.String&gt;&gt;** | Delegations that are automatically generated client side when a new database object is created by this user | 
**applicationTokens** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** | Long lived authentication tokens used for inter-applications authentication. | 
**authenticationTokens** | [**kotlin.collections.Map&lt;kotlin.String, AuthenticationTokenDto&gt;**](AuthenticationTokenDto.md) | Encrypted and time-limited Authentication tokens used for inter-applications authentication | 
**rev** | **kotlin.String** | the revision of the user in the database, used for conflict management / optimistic locking. |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**created** | **kotlin.Long** |  |  [optional]
**name** | **kotlin.String** | Last name of the user. This is the official last name that should be used for official administrative purposes. |  [optional]
**type** | [**inline**](#TypeEnum) | Authorization source for user. &#39;Database&#39;, &#39;ldap&#39; or &#39;token&#39; |  [optional]
**status** | [**inline**](#StatusEnum) | State of user&#39;s activeness: &#39;Active&#39;, &#39;Disabled&#39; or &#39;Registering&#39; |  [optional]
**login** | **kotlin.String** | Username for this user. We encourage using an email address |  [optional]
**passwordHash** | **kotlin.String** | Hashed version of the password (BCrypt is used for hashing) |  [optional]
**secret** | **kotlin.String** | Secret token used to verify 2fa |  [optional]
**use2fa** | **kotlin.Boolean** | Whether the user has activated two factors authentication |  [optional]
**groupId** | **kotlin.String** | id of the group (practice/hospital) the user is member of |  [optional]
**healthcarePartyId** | **kotlin.String** | Id of the healthcare party if the user is a healthcare party. |  [optional]
**patientId** | **kotlin.String** | Id of the patient if the user is a patient |  [optional]
**createdDate** | [**java.time.OffsetDateTime**](java.time.OffsetDateTime.md) | the timestamp (unix epoch in ms) of creation of the user, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**termsOfUseDate** | [**java.time.OffsetDateTime**](java.time.OffsetDateTime.md) | the timestamp (unix epoch in ms) of the latest validation of the terms of use of the application |  [optional]
**email** | **kotlin.String** | email address of the user. |  [optional]


<a name="TypeEnum"></a>
## Enum: type
Name | Value
---- | -----
type | database, ldap, token


<a name="StatusEnum"></a>
## Enum: status
Name | Value
---- | -----
status | ACTIVE, DISABLED, REGISTERING



