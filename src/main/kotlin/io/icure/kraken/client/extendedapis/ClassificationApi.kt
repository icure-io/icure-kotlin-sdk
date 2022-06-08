package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.ClassificationApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.DelegationDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.ClassificationDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun ClassificationDto.initDelegations(user: UserDto, config: CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>): ClassificationDto {
    val delegations =  (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    val ek = UUID.randomUUID().toString()
    val sfk = UUID.randomUUID().toString()
    return this.copy(
        responsible = user.dataOwnerId(),
        author = user.id,
        delegations = (delegations + user.dataOwnerId()).fold(this.delegations) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    emptyList(), user.dataOwnerId(), d, config.crypto.encryptAESKeyForDataOwner(user.dataOwnerId(), d, this.id, sfk).first,
                ),
            ))
        },
        encryptionKeys = (delegations + user.dataOwnerId()).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    emptyList(), user.dataOwnerId(), d, config.crypto.encryptAESKeyForDataOwner(user.dataOwnerId(), d, this.id, ek).first,
                ),
            ))
        },
    )
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.createClassification(user: UserDto, classification: ClassificationDto, config: CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>) =
    this.createClassification(
        config.encryptClassification(
            user.dataOwnerId(),
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            classification
        )
    ).let { config.decryptClassification(user.dataOwnerId(), it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.getClassificationByHcPartyId(user: UserDto, ids: String, config: CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>) : List<ClassificationDto> {
    return this.getClassificationByHcPartyId(ids).map { config.decryptClassification(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.newClassificationDelegations(user: UserDto, classificationId: String, delegationDto: List<DelegationDto>, config: CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>) : ClassificationDto {
    return this.newClassificationDelegations(classificationId, delegationDto).let { config.decryptClassification(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.findByHCPartyPatient(user: UserDto, hcPartyId: String, patient: PatientDto, config: CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>) : List<ClassificationDto>? {
    val keys = config.crypto.decryptEncryptionKeys(user.dataOwnerId(), patient.delegations).takeIf { it.isNotEmpty() } ?: throw IllegalArgumentException("No delegation for user")
    return this.findClassificationsByHCPartyPatientForeignKeys(user, hcPartyId, keys.joinToString(","), config)
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.findClassificationsByHCPartyPatientForeignKeys(user: UserDto, hcPartyId: String, secretFKeys: String, config: CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>) : List<ClassificationDto> {
    return this.findClassificationsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys).map { config.decryptClassification(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.getClassification(user: UserDto, classificationId: String, config: CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>): ClassificationDto  {
    return this.getClassification(classificationId).let { config.decryptClassification(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ClassificationApi.modifyClassification(user: UserDto, classification: ClassificationDto, config: CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>) : ClassificationDto  {
    return this.modifyClassification(
        config.encryptClassification(
            user.dataOwnerId(),
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            classification
        )
    ).let { config.decryptClassification(user.dataOwnerId(), it) }
}

suspend fun CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>.encryptClassification(myId: String, delegations: Set<String>, classification: ClassificationDto): io.icure.kraken.client.models.ClassificationDto {
    return if (classification.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        classification
    } else {
        val secret = UUID.randomUUID().toString()
        classification.copy(encryptionKeys = (delegations + myId).fold(classification.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(emptyList(), myId, d, this.crypto.encryptAESKeyForDataOwner(myId, d, classification.id, secret).first)))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.replace(
            "-",
            ""
        )?.keyFromHexString() ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedClassification, marshalledData) = this.marshaller(p)
        sanitizedClassification.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key)))
    }
}

suspend fun CryptoConfig<ClassificationDto, io.icure.kraken.client.models.ClassificationDto>.decryptClassification(myId: String, classification: io.icure.kraken.client.models.ClassificationDto): ClassificationDto {
    val key = this.crypto.decryptEncryptionKeys(myId, classification.encryptionKeys).firstOrNull()?.replace(
        "-",
        ""
    )?.keyFromHexString() ?: throw IllegalArgumentException("No encryption key for user")
    return this.unmarshaller(classification, decryptAES(data = Base64.getDecoder().decode(classification.encryptedSelf), key = key))
}


