
# ReplicatorDocument

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**id** | **kotlin.String** |  | 
**rev** | **kotlin.String** |  |  [optional]
**source** | [**Remote**](Remote.md) |  |  [optional]
**target** | [**Remote**](Remote.md) |  |  [optional]
**owner** | **kotlin.String** |  |  [optional]
**createTarget** | **kotlin.Boolean** |  |  [optional]
**continuous** | **kotlin.Boolean** |  |  [optional]
**docIds** | **kotlin.collections.List&lt;kotlin.String&gt;** |  |  [optional]
**replicationState** | **kotlin.String** |  |  [optional]
**replicationStateTime** | [**java.time.OffsetDateTime**](java.time.OffsetDateTime.md) |  |  [optional]
**replicationStats** | [**ReplicationStats**](ReplicationStats.md) |  |  [optional]
**errorCount** | **kotlin.Int** |  |  [optional]
**revsInfo** | **kotlin.collections.List&lt;kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;&gt;** |  |  [optional]
**revHistory** | **kotlin.collections.Map&lt;kotlin.String, kotlin.String&gt;** |  |  [optional]



