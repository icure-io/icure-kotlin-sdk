package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.AccesslogApi
import io.icure.kraken.client.apis.ClassificationApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.fromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.AccessLogDto
import io.icure.kraken.client.models.decrypted.ClassificationDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun ClassificationDto.initDelegations(user: UserDto, config: CryptoConfig<ClassificationDto>): ClassificationDto {
    val delegations =  (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    val ek = UUID.randomUUID().toString()
    val sfk = UUID.randomUUID().toString()
    return this.copy(
        responsible = user.healthcarePartyId!!,
        author = user.id,
        delegations = (delegations + user.healthcarePartyId!!).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    listOf(), user.healthcarePartyId, d, config.crypto.encryptKeyForHcp(user.healthcarePartyId, d, this.id, sfk),
                ),
            ))
        },
        encryptionKeys = (delegations + user.healthcarePartyId!!).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    listOf(), user.healthcarePartyId, d, config.crypto.encryptKeyForHcp(user.healthcarePartyId, d, this.id, ek),
                ),
            ))
        },
    )
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.createClassification(user: UserDto, classification: ClassificationDto, config: CryptoConfig<ClassificationDto>) =
    this.createClassification(
        config.encryptClassification(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            classification
        )
    )?.let { config.decryptClassification(user.healthcarePartyId!!, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.getClassificationByHcPartyId(user: UserDto, ids: String, config: CryptoConfig<ClassificationDto>) : List<ClassificationDto>? {
    return this.getClassificationByHcPartyId(ids)?.map { config.decryptClassification(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.newClassificationDelegations(user: UserDto, classificationId: String, delegationDto: List<DelegationDto>, config: CryptoConfig<ClassificationDto>) : ClassificationDto? {
    return this.newClassificationDelegations(classificationId, delegationDto)?.let { config.decryptClassification(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.findByHCPartyPatient(user: UserDto, hcPartyId: String, patient: PatientDto, config: CryptoConfig<ClassificationDto>) : List<ClassificationDto>? {
    val key = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, patient.delegations).firstOrNull() ?: throw IllegalArgumentException("No delegation for user")
    return this.findClassificationsByHCPartyPatientForeignKeys(user, hcPartyId, key, config)
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.findClassificationsByHCPartyPatientForeignKeys(user: UserDto, hcPartyId: String, secretFKeys: String, config: CryptoConfig<ClassificationDto>) : List<ClassificationDto>? {
    return this.findClassificationsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)?.map { config.decryptClassification(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.getClassification(user: UserDto, classificationId: String, config: CryptoConfig<ClassificationDto>): ClassificationDto?  {
    return this.getClassification(classificationId)?.let { config.decryptClassification(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.modifyClassification(user: UserDto, classification: ClassificationDto, config: CryptoConfig<ClassificationDto>) : ClassificationDto?  {
    return this.modifyClassification(
        config.encryptClassification(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            classification
        )
    )?.let { config.decryptClassification(user.healthcarePartyId!!, it) }
}

suspend fun CryptoConfig<ClassificationDto>.encryptClassification(myId: String, delegations: Set<String>, classification: ClassificationDto): io.icure.kraken.client.models.ClassificationDto {
    return if (classification.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        classification
    } else {
        val secret = UUID.randomUUID().toString()
        classification.copy(encryptionKeys = (delegations + myId).fold(classification.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptKeyForHcp(myId, d, classification.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).fromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedClassification, marshalledData) = this.marshaller(p)
        ClassificationMapperFactory.instance.map(sanitizedClassification.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key))))
    }
}

suspend fun CryptoConfig<ClassificationDto>.decryptClassification(myId: String, classification: io.icure.kraken.client.models.ClassificationDto): ClassificationDto = ClassificationMapperFactory.instance.map(classification).let { p ->
    val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).fromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    this.unmarshaller(p, decryptAES(data = Base64.getDecoder().decode(p.encryptedSelf), key = key))
}

@Mapper
interface ClassificationMapper {
    fun map(classification: ClassificationDto): io.icure.kraken.client.models.ClassificationDto
    fun map(classification: io.icure.kraken.client.models.ClassificationDto): ClassificationDto
}

object ClassificationMapperFactory {
    val instance = Mappers.getMapper(ClassificationMapper::class.java)
}
