package io.icure.kraken.client.extendedapis

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import io.icure.kraken.client.apis.DeviceApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.applyIf
import io.icure.kraken.client.defGet
import io.icure.kraken.client.defPut
import io.icure.kraken.client.models.DeviceDto
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.PatientDto
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.flattenMerge
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import java.util.*
import java.util.concurrent.TimeUnit

@FlowPreview
@ExperimentalStdlibApi
@ExperimentalCoroutinesApi
class DataOwnerResolver(
    private val hcpartyApi: HealthcarePartyApi,
    private val patientApi: PatientApi,
    private val deviceApi: DeviceApi
) {
    private val hcParties : Cache<String, Deferred<Optional<HealthcarePartyDto>>> = Caffeine.newBuilder()
        .maximumSize(100)
        .expireAfterWrite(5, TimeUnit.MINUTES)
        .build()

    private val patients : Cache<String, Deferred<Optional<PatientDto>>> = Caffeine.newBuilder()
        .maximumSize(100)
        .expireAfterWrite(5, TimeUnit.MINUTES)
        .build()

    private val devices : Cache<String, Deferred<Optional<DeviceDto>>> = Caffeine.newBuilder()
        .maximumSize(100)
        .expireAfterWrite(5, TimeUnit.MINUTES)
        .build()

    /**
     * This method updates the Data Owner after adding the new hcPartyKeys (or aesExchangeKeys) provided in argument.
     *
     * @param dataOwnerType HCP - Patient or Device
     * @param dataOwnerId Id of the delegator Data Owner
     * @param newHcPartyKeysForPubKey This pair contains the delegator publicKey as first arg and, as second
     * arg, a new pair composed of the delegate id and the list of the data owner AES_KEY, encrypted once for
     * every needed public key (first one is the one of the delegator, next ones are the ones of the delegate, issued
     * from its aesExchangeKeys field)
     *
     * @return the updated data owner
     */
    suspend fun updateDataOwnerWithNewHcPartyKeys(dataOwnerType: DataOwnerType, dataOwnerId: String, newHcPartyKeysForPubKey: Map<String, Pair<String, List<Pair<String, String>>>>) : DataOwner {
        return when(dataOwnerType) {
            DataOwnerType.HCP -> hcParties.defGet(dataOwnerId) { hcpartyApi.getHealthcareParty(dataOwnerId) }
                ?.let { hcp ->
                    val updatedHcp = hcpartyApi.modifyHealthcareParty(createHcpWithUpdatedHcPartyKeys(hcp, newHcPartyKeysForPubKey))
                    hcParties.defPut(dataOwnerId) { updatedHcp }
                    updatedHcp
                }
                ?.toDataOwner()
            DataOwnerType.PATIENT -> patients.defGet(dataOwnerId) { patientApi.getPatient(dataOwnerId) }
                ?.let { patient ->
                    val updatedPatient = patientApi.modifyPatient(createPatientWithUpdatedHcPartyKeys(patient, newHcPartyKeysForPubKey))
                    patients.defPut(dataOwnerId) { updatedPatient }
                    updatedPatient
                }
                ?.toDataOwner()
            DataOwnerType.DEVICE -> devices.defGet(dataOwnerId) { deviceApi.getDevice(dataOwnerId) }
                ?.let { device ->
                    val updatedDevice = deviceApi.updateDevice(createDeviceWithUpdatedHcPartyKeys(device, newHcPartyKeysForPubKey))
                    devices.defPut(dataOwnerId) { updatedDevice }
                    updatedDevice
                }
                ?.toDataOwner()
        } ?: throw RuntimeException("Could not add new hcpartyKeys to data owner $dataOwnerId")
    }

    private fun createHcpWithUpdatedHcPartyKeys(hcp: HealthcarePartyDto, newHcPartyKeysForPubKey: Map<String, Pair<String, List<Pair<String, String>>>>): HealthcarePartyDto {
        return hcp.toDataOwner()
            .updateAesExchangeKeys(newHcPartyKeysForPubKey)
            .let { dataOwner ->
                hcp.copy(hcPartyKeys = dataOwner.hcPartyKeys, aesExchangeKeys = dataOwner.aesExchangeKeys)
            }
    }

    private fun createPatientWithUpdatedHcPartyKeys(patient: PatientDto, newHcPartyKeysForPubKey: Map<String, Pair<String, List<Pair<String, String>>>>): PatientDto {
        return patient.toDataOwner()
            .updateAesExchangeKeys(newHcPartyKeysForPubKey)
            .let { dataOwner ->
                patient.copy(hcPartyKeys = dataOwner.hcPartyKeys, aesExchangeKeys = dataOwner.aesExchangeKeys)
            }
    }

    private fun createDeviceWithUpdatedHcPartyKeys(device: DeviceDto, newHcPartyKeysForPubKey: Map<String, Pair<String, List<Pair<String, String>>>>): DeviceDto {
        return device.toDataOwner()
            .updateAesExchangeKeys(newHcPartyKeysForPubKey)
            .let { dataOwner ->
                device.copy(hcPartyKeys = dataOwner.hcPartyKeys, aesExchangeKeys = dataOwner.aesExchangeKeys)
            }
    }

    suspend fun getDataOwnerHcPartyKeysForDelegate(delegateId: String) : Map<String, Map<String, Map<String, String>>> {
        return flowOf(
            flow { emit(try {
                hcpartyApi.getAesExchangeKeysForDelegate(delegateId)
            } catch(e: Exception) {
                emptyMap()
            }) },
            flow { emit(try {
                patientApi.getPatientAesExchangeKeysForDelegate(delegateId)
            } catch(e: Exception) {
                emptyMap()
            }) },
            flow { emit(try { deviceApi.getDeviceAesExchangeKeysForDelegate(delegateId) } catch(e: Exception) { emptyMap() }) }
        )
            .flattenMerge(3)
            .filter { hcPartyKeys -> hcPartyKeys.isNotEmpty() }
            .toList(mutableListOf())
            .flatMap { map -> map.entries }
            .associate { (key, value) -> key to value }
    }

    suspend fun getDataOwner(dataOwnerId: String) : DataOwner {
        return flowOf(
            flow { emit(getHcpDataOwner(dataOwnerId)) },
            flow { emit(getPatientDataOwner(dataOwnerId)) },
            flow { emit(getDeviceDataOwner(dataOwnerId)) }
        )
            .flattenMerge(3)
            .filterNotNull()
            .firstOrNull()
            ?: throw IllegalArgumentException("$dataOwnerId is not a data owner")
    }

    private suspend fun getHcpDataOwner(hcpId: String) : DataOwner? {
        return try {
            hcParties.defGet(hcpId) { hcpartyApi.getHealthcareParty(hcpId) }?.toDataOwner()
        } catch (e: Exception) { null }
    }

    private suspend fun getPatientDataOwner(patientId: String) : DataOwner? {
        return try {
            patients.defGet(patientId) { patientApi.getPatient(patientId) }?.toDataOwner()
        } catch (e: Exception) { null }
    }

    private suspend fun getDeviceDataOwner(deviceId: String) : DataOwner? {
        return try {
            devices.defGet(deviceId) { deviceApi.getDevice(deviceId) }?.toDataOwner()
        } catch (e: Exception) { null }
    }
}

fun HealthcarePartyDto.toDataOwner() : DataOwner {
    return DataOwner(
        type = DataOwnerType.HCP,
        dataOwnerId = this.id,
        rev = this.rev,
        publicKey = this.publicKey,
        hcPartyKeys = this.hcPartyKeys,
        aesExchangeKeys = this.aesExchangeKeys,
        transferKeys = this.transferKeys,
        parentId = this.parentId
    )
}

fun PatientDto.toDataOwner() : DataOwner {
    return DataOwner(
        type = DataOwnerType.PATIENT,
        dataOwnerId = this.id,
        rev = this.rev,
        publicKey = this.publicKey,
        hcPartyKeys = this.hcPartyKeys,
        aesExchangeKeys = this.aesExchangeKeys,
        transferKeys = this.transferKeys
    )
}

fun io.icure.kraken.client.models.decrypted.PatientDto.toDataOwner() : DataOwner {
    return DataOwner(
        type = DataOwnerType.PATIENT,
        dataOwnerId = this.id,
        rev = this.rev,
        publicKey = this.publicKey,
        hcPartyKeys = this.hcPartyKeys,
        aesExchangeKeys = this.aesExchangeKeys,
        transferKeys = this.transferKeys
    )
}

fun DeviceDto.toDataOwner() : DataOwner {
    return DataOwner(
        type = DataOwnerType.DEVICE,
        dataOwnerId = this.id,
        rev = this.rev,
        publicKey = this.publicKey,
        hcPartyKeys = this.hcPartyKeys,
        aesExchangeKeys = this.aesExchangeKeys,
        transferKeys = this.transferKeys,
        parentId = this.parentId
    )
}

data class DataOwner(
    val type: DataOwnerType,
    val dataOwnerId: String,
    val rev: String?,
    val publicKey: String? = null,
    val hcPartyKeys: Map<String, List<String>> = emptyMap(),
    val aesExchangeKeys: Map<String, Map<String, Map<String, String>>> = emptyMap(),
    val transferKeys: Map<String, Map<String, String>> = emptyMap(),
    val parentId: String? = null
) {
    /**
     * Finds all aesExchangeKeys of a dataOwner for each of its publicKey.
     * The structure of the returned Map is the following :
     * { doPubKey1: { hcp1Id: encAes1WithPubKey1, hcp2Id: encAes2WithPubKey1 }, doPubKey2: { hcp1Id: encAes2WithPubKey2 } }
     *
     */
    fun findRelatedHcPartyKeys(dataOwnerPublicKeys: List<String>): Map<String, Map<String, String>> {
        return dataOwnerPublicKeys.fold(emptyMap()) { doAesKeys, pubKey ->
            if (this.publicKey == pubKey && this.hcPartyKeys.isNotEmpty()) {
                doAesKeys.plus(pubKey to this.hcPartyKeys.mapValues { (_, v) -> v[0] })
            } else {
                val slicedPubKey = pubKey.takeLast(12)
                doAesKeys.plus(pubKey to (this.aesExchangeKeys[slicedPubKey]?.mapValues { (delegateId, v) ->
                    v[slicedPubKey] ?: throw IllegalArgumentException("Could not find $slicedPubKey in aesExchangeKeys values of $delegateId")
                } ?: emptyMap()))
            }

            doAesKeys
        }
    }

    fun updateAesExchangeKeys(
        newAesExchangeKeysForPubKeys: Map<String, Pair<String, List<Pair<String, String>>>>
    ) : DataOwner {
        return this
            .addNewAesExchangeKeys(newAesExchangeKeysForPubKeys)
            .applyIf({ dataOwner -> dataOwner.publicKey in newAesExchangeKeysForPubKeys.keys }) { dataOwner ->
                dataOwner.addNewHcPartyKeys(newAesExchangeKeysForPubKeys[dataOwner.publicKey]!!)
            }
    }
    private fun addNewAesExchangeKeys(
        newAesExchangeKeys: Map<String, Pair<String, List<Pair<String, String>>>>,
    ): DataOwner {
        val mappedAesExchangeKeys = newAesExchangeKeys.mapValues { (_, aesKeys) ->
            aesKeys.let { (delegateId, keys) ->
                delegateId to keys.associate { (pubKey, encKey) ->
                    pubKey.takeLast(12) to encKey
                }
            }
        }

        val existingAesExchangeKeys = mappedAesExchangeKeys.toList().fold(this.aesExchangeKeys.toMutableMap()) { existingKeys, (dataOwnerPubKey, newAesExchangeKey) ->
            existingKeys.merge(dataOwnerPubKey, mapOf(newAesExchangeKey)) { previousKeys, newKeys -> previousKeys + newKeys }
            existingKeys
        }

        return this.copy(aesExchangeKeys = existingAesExchangeKeys)
    }

    private fun addNewHcPartyKeys(
        newHcPartyKeys: Pair<String, List<Pair<String, String>>>
    ): DataOwner {
        val (delegateId, keys) = newHcPartyKeys
        val existingHcPartyKeys = this.hcPartyKeys.toMutableMap().let {
            it[delegateId] = keys.subList(0, 2).map { (_, key) -> key }
            it
        }.toMap()
        return this.copy(hcPartyKeys = existingHcPartyKeys)
    }


}

enum class DataOwnerType {
    HCP,
    DEVICE,
    PATIENT;
}
