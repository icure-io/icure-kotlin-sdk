package io.icure.kraken.client.extendedapis

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import io.icure.kraken.client.apis.DeviceApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.defGet
import io.icure.kraken.client.defPut
import io.icure.kraken.client.models.DeviceDto
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.PatientDto
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.emitAll
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
    suspend fun updateDataOwnerWithNewHcPartyKeys(dataOwnerType: DataOwnerType, dataOwnerId: String, newHcPartyKeysForPubKey: Pair<String, Pair<String, List<String>>>) : DataOwner {
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

    private fun createHcpWithUpdatedHcPartyKeys(hcp: HealthcarePartyDto, newHcPartyKeysForPubKey: Pair<String, Pair<String, List<String>>>): HealthcarePartyDto {
        val (dataOwnerPubKey, newHcPartyKeys) = newHcPartyKeysForPubKey
        val updatedAesExchangeKeys = addNewAesExchangeKeys(hcp.aesExchangeKeys, dataOwnerPubKey, newHcPartyKeys)

        return if (dataOwnerPubKey == hcp.publicKey && hcp.hcPartyKeys.isNotEmpty()) {
            hcp.copy(
                hcPartyKeys = addNewHcPartyKeys(hcp.hcPartyKeys, newHcPartyKeys),
                aesExchangeKeys = updatedAesExchangeKeys
            )
        } else {
            hcp.copy(aesExchangeKeys = updatedAesExchangeKeys)
        }
    }

    private fun createPatientWithUpdatedHcPartyKeys(patient: PatientDto, newHcPartyKeysForPubKey: Pair<String, Pair<String, List<String>>>): PatientDto {
        val (dataOwnerPubKey, newHcPartyKeys) = newHcPartyKeysForPubKey
        val updatedAesExchangeKeys = addNewAesExchangeKeys(patient.aesExchangeKeys, dataOwnerPubKey, newHcPartyKeys)

        return if (dataOwnerPubKey == patient.publicKey) {
            patient.copy(hcPartyKeys = addNewHcPartyKeys(patient.hcPartyKeys, newHcPartyKeys), aesExchangeKeys = updatedAesExchangeKeys)
        } else {
            patient.copy(aesExchangeKeys = updatedAesExchangeKeys)
        }
    }
    private fun createDeviceWithUpdatedHcPartyKeys(device: DeviceDto, newHcPartyKeysForPubKey: Pair<String, Pair<String, List<String>>>): DeviceDto {
        val (dataOwnerPubKey, newHcPartyKeys) = newHcPartyKeysForPubKey
        val updatedAesExchangeKeys = addNewAesExchangeKeys(device.aesExchangeKeys, dataOwnerPubKey, newHcPartyKeys)

        return if (dataOwnerPubKey == device.publicKey) {
            device.copy(hcPartyKeys = addNewHcPartyKeys(device.hcPartyKeys, newHcPartyKeys), aesExchangeKeys = updatedAesExchangeKeys)
        } else {
            device.copy(aesExchangeKeys = updatedAesExchangeKeys)
        }
    }

    private fun addNewAesExchangeKeys(
        existingAesExchangeKeys: Map<String, Map<String, List<String>>>,
        dataOwnerPubKey: String,
        newHcPartyKeys: Pair<String, List<String>>
    ): Map<String, Map<String, List<String>>> = existingAesExchangeKeys.let {
        val mutableAesKeys = it.toMutableMap()
        mutableAesKeys
            .merge(dataOwnerPubKey, mapOf(newHcPartyKeys)) { previousKeys, newKeys -> previousKeys + newKeys }
        mutableAesKeys
    }

    private fun addNewHcPartyKeys(
        existingHcPartyKeys: Map<String, List<String>>,
        newHcPartyKeys: Pair<String, List<String>>
    ): Map<String, List<String>> {
        val (delegateId, keys) = newHcPartyKeys
        return existingHcPartyKeys.toMutableMap().let {
            it[delegateId] = keys.subList(0, 2)
            it
        }.toMap()
    }

    suspend fun getDataOwnerHcPartyKeysForDelegate(delegateId: String) : Map<String, List<String>> {
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
        aesExchangeKeys = this.aesExchangeKeys
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
        parentId = this.parentId
    )
}

data class DataOwner(
    val type: DataOwnerType,
    val dataOwnerId: String,
    val rev: String?,
    val publicKey: String? = null,
    val hcPartyKeys: Map<String, List<String>> = emptyMap(),
    val aesExchangeKeys: Map<String, Map<String, List<String>>> = emptyMap(),
    val parentId: String? = null
) {
    fun findRelatedHcPartyKeys(dataOwnerPublicKey: String): Map<String, List<String>> {
        return if (this.publicKey == dataOwnerPublicKey && this.hcPartyKeys.isNotEmpty()) this.hcPartyKeys else this.aesExchangeKeys[dataOwnerPublicKey] ?: emptyMap()
    }
}

enum class DataOwnerType {
    HCP,
    DEVICE,
    PATIENT;
}
