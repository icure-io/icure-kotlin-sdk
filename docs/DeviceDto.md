
# DeviceDto

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** |  | 
**identifiers** | [**kotlin.collections.List&lt;IdentifierDto&gt;**](IdentifierDto.md) |  | 
**tags** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A tag is an item from a codification system that qualifies an entity as being member of a certain class, whatever the value it might have taken. If the tag qualifies the content of a field, it means that whatever the content of the field, the tag will always apply. For example, the label of a field is qualified using a tag. LOINC is a codification system typically used for tags. | 
**codes** | [**kotlin.collections.Set&lt;CodeStubDto&gt;**](CodeStubDto.md) | A code is an item from a codification system that qualifies the content of this entity. SNOMED-CT, ICPC-2 or ICD-10 codifications systems can be used for codes | 
**properties** | [**kotlin.collections.Set&lt;PropertyStubDto&gt;**](PropertyStubDto.md) |  | 
**hcPartyKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;kotlin.String&gt;&gt;** | For each couple of HcParties (delegator and delegate), this map contains the exchange AES key. The delegator is always this hcp, the key of the map is the id of the delegate. The AES exchange key is encrypted using RSA twice : once using this hcp public key (index 0 in the Array) and once using the other hcp public key (index 1 in the Array). For a pair of HcParties. Each HcParty always has one AES exchange key for himself. | 
**aesExchangeKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Map&lt;kotlin.String, kotlin.collections.List&lt;kotlin.String&gt;&gt;&gt;** | Extra AES exchange keys, usually the ones we lost access to at some point. The structure is { publicKey: { delegateId: [aesExKey_for_this, aesExKey_for_delegate] } } | 
**transferKeys** | **kotlin.collections.Map&lt;kotlin.String, kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;&gt;** | Our private keys encrypted with our public keys. The structure is { publicKey1: { publicKey2: privateKey2_encrypted_with_publicKey1, publicKey3: privateKey3_encrypted_with_publicKey1 } } | 
**privateKeyShamirPartitions** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** | The privateKeyShamirPartitions are used to share this hcp&#39;s private RSA key with a series of other hcParties using Shamir&#39;s algorithm. The key of the map is the hcp Id with whom this partition has been shared. The value is \&quot;threshold⎮partition in hex\&quot; encrypted using the the partition&#39;s holder&#39;s public RSA key | 
**rev** | **kotlin.String** |  |  [optional]
**deletionDate** | **kotlin.Long** | hard delete (unix epoch in ms) timestamp of the object. Filled automatically when deletePatient is called. |  [optional]
**created** | **kotlin.Long** | The timestamp (unix epoch in ms) of creation of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**modified** | **kotlin.Long** | The date (unix epoch in ms) of the latest modification of this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**author** | **kotlin.String** | The id of the User that has created this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**responsible** | **kotlin.String** | The id of the HealthcareParty that is responsible for this entity, will be filled automatically if missing. Not enforced by the application server. |  [optional]
**endOfLife** | **kotlin.Long** | Soft delete (unix epoch in ms) timestamp of the object. |  [optional]
**medicalLocationId** | **kotlin.String** | The id of the medical location where this entity was created. |  [optional]
**externalId** | **kotlin.String** |  |  [optional]
**name** | **kotlin.String** |  |  [optional]
**type** | **kotlin.String** |  |  [optional]
**brand** | **kotlin.String** |  |  [optional]
**model** | **kotlin.String** |  |  [optional]
**serialNumber** | **kotlin.String** |  |  [optional]
**parentId** | **kotlin.String** |  |  [optional]
**picture** | [**kotlin.collections.List&lt;io.icure.kraken.client.infrastructure.ByteArrayWrapper&gt;**](io.icure.kraken.client.infrastructure.ByteArrayWrapper.md) |  |  [optional]
**publicKey** | **kotlin.String** | The public key of this hcp |  [optional]



