package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.DeviceApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.models.DeviceDto
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
class DataOwnerApi(val healthcarePartyApi: HealthcarePartyApi, val patientApi: PatientApi, val deviceApi: DeviceApi) {
    suspend inline fun <reified T> getDataOwner(dataOwnerId: String): T? {
        return try {
            when(T::class){
                HealthcarePartyDto::class -> healthcarePartyApi.getHealthcareParty(dataOwnerId) as? T?
                PatientDto::class -> patientApi.getPatient(dataOwnerId) as? T?
                DeviceDto::class -> deviceApi.getDevice(dataOwnerId) as? T?
                else -> null
            }
        } catch (e: Exception){
            null
        }
    }
    suspend fun createDataOwner(dataOwner: HealthcarePartyDto): HealthcarePartyDto {
        return healthcarePartyApi.createHealthcareParty(dataOwner)
    }

    suspend fun createDataOwner(dataOwner: PatientDto): PatientDto {
        return patientApi.createPatient(dataOwner)
    }

    suspend fun createDataOwner(dataOwner: DeviceDto): DeviceDto {
        return deviceApi.createDevice(dataOwner)
    }

    suspend fun modifyDataOwner(dataOwner: HealthcarePartyDto): HealthcarePartyDto {
        return healthcarePartyApi.modifyHealthcareParty(dataOwner)
    }

    suspend fun modifyDataOwner(dataOwner: PatientDto): PatientDto {
        return patientApi.modifyPatient(dataOwner)
    }

    suspend fun modifyDataOwner(dataOwner: DeviceDto): DeviceDto {
        return deviceApi.updateDevice(dataOwner)
    }
}

