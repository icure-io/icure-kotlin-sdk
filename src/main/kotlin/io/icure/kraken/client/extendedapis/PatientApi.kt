package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.crypto.Crypto
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.CryptoUtils.decodeHex
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.models.DelegationDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.createPatient(user: UserDto, patient: PatientDto, config: CryptoConfig<PatientDto>) =
    this.createPatient(
        config.encryptPatient(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            patient
        )
    )?.let { config.decryptPatient(user.healthcarePartyId!!, it) }

suspend fun CryptoConfig<PatientDto>.encryptPatient(myId: String, delegations: Set<String>, patient: PatientDto): io.icure.kraken.client.models.PatientDto {
    return if (patient.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        patient
    } else {
        val secret = UUID.randomUUID().toString()
        patient.copy(encryptionKeys = (delegations + myId).fold(patient.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptKeyForHcp(myId, d, patient.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey -> decodeHex(aesKey.replace("-", "")) } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedPatient, marshalledData) = this.marshaller(p)
        PatientMapperFactory.instance.map(sanitizedPatient.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData.toByteArray(Charsets.UTF_8), key = key))))
    }
}

suspend fun CryptoConfig<PatientDto>.decryptPatient(myId: String, patient: io.icure.kraken.client.models.PatientDto): PatientDto = PatientMapperFactory.instance.map(patient).let { p ->
    val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey -> decodeHex(aesKey.replace("-", "")) } ?: throw IllegalArgumentException("No encryption key for user")
    this.unmarshaller(p, decryptAES(data = Base64.getDecoder().decode(p.encryptedSelf), key = key).toString(Charsets.UTF_8))
}

@Mapper
interface PatientMapper {
    fun map(patient: PatientDto): io.icure.kraken.client.models.PatientDto
    fun map(patient: io.icure.kraken.client.models.PatientDto): PatientDto
}

object PatientMapperFactory {
    val instance = Mappers.getMapper(PatientMapper::class.java)
}
