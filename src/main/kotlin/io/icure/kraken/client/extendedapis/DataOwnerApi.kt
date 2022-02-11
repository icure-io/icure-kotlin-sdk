package io.icure.kraken.client.extendedapis

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import io.icure.kraken.client.apis.DeviceApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.defGet
import io.icure.kraken.client.models.DeviceDto
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.PatientDto
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.collect
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

    suspend fun updateDataOwnerWithNewHcPartyKeys(dataOwnerType: DataOwnerType, dataOwnerId: String, newHcPartyKeys: Pair<String, List<String>>) : DataOwner {
        return when(dataOwnerType) {
            DataOwnerType.HCP -> hcParties.defGet(dataOwnerId) { hcpartyApi.getHealthcareParty(dataOwnerId) }
                ?.let { hcpartyApi.modifyHealthcareParty(it.copy(hcPartyKeys = it.hcPartyKeys + newHcPartyKeys)) }
                ?.toDataOwner()
            DataOwnerType.PATIENT -> patients.defGet(dataOwnerId) { patientApi.getPatient(dataOwnerId) }
                ?.let { patientApi.modifyPatient(it.copy(hcPartyKeys = it.hcPartyKeys + newHcPartyKeys)) }
                ?.toDataOwner()
            DataOwnerType.DEVICE -> devices.defGet(dataOwnerId) { deviceApi.getDevice(dataOwnerId) }
                ?.let { deviceApi.updateDevice(it.copy(hcPartyKeys = it.hcPartyKeys + newHcPartyKeys)) }
                ?.toDataOwner()
        } ?: throw RuntimeException("Could not add new hcpartyKeys to data owner $dataOwnerId")
    }

    suspend fun getDataOwnerHcPartyKeysForDelegate(delegateId: String) : Map<String, String> {
        return flowOf(
            flow { emit(try { hcpartyApi.getHcPartyKeysForDelegate(delegateId) } catch(e: Exception) { emptyMap() }) },
            flow { emit(try { patientApi.getPatientHcPartyKeysForDelegate(delegateId) } catch(e: Exception) { emptyMap() }) },
            flow { emit(try { deviceApi.getDeviceHcPartyKeysForDelegate(delegateId) } catch(e: Exception) { emptyMap() }) }
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
    return DataOwner(DataOwnerType.HCP, this.id, this.publicKey, this.hcPartyKeys, this.parentId)
}

fun PatientDto.toDataOwner() : DataOwner {
    return DataOwner(DataOwnerType.PATIENT, this.id, this.publicKey, this.hcPartyKeys)
}

fun DeviceDto.toDataOwner() : DataOwner {
    return DataOwner(DataOwnerType.DEVICE, this.id, this.publicKey, this.hcPartyKeys, this.parentId)
}

data class DataOwner(
    val type: DataOwnerType,
    val dataOwnerId: String,
    val publicKey: String? = null,
    val hcPartyKeys: Map<String, List<String>> = emptyMap(),
    val parentId: String? = null
)

enum class DataOwnerType {
    HCP,
    DEVICE,
    PATIENT;
}