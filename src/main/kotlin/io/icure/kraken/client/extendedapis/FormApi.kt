package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.FormApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.FormDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun FormDto.initDelegations(user: UserDto, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>): FormDto {
    val delegations = (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    val ek = UUID.randomUUID().toString()
    val sfk = UUID.randomUUID().toString()
    return this.copy(
        responsible = user.healthcarePartyId!!,
        author = user.id,
        delegations = (delegations + user.healthcarePartyId!!).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    listOf(),
                    user.healthcarePartyId,
                    d,
                    config.crypto.encryptKeyForHcp(user.healthcarePartyId, d, this.id, sfk),
                ),
            ))
        },
        encryptionKeys = (delegations + user.healthcarePartyId!!).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    listOf(),
                    user.healthcarePartyId,
                    d,
                    config.crypto.encryptKeyForHcp(user.healthcarePartyId, d, this.id, ek),
                ),
            ))
        },
    )
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.createForm(user: UserDto, form: FormDto, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>) =
    this.createForm(
        config.encryptForm(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            form
        )
    )?.let {
        config.decryptForm(user.healthcarePartyId!!, it)
    }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.newFormDelegations(
    user: UserDto,
    formId: String,
    delegationDto: List<DelegationDto>,
    config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>
): FormDto? {
    return this.newFormDelegations(formId, delegationDto)?.let { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.findByHCPartyPatient(
    user: UserDto,
    hcPartyId: String,
    patient: PatientDto,
    healthElementId: String?,
    planOfActionId: String?,
    formTemplateId: String?,
    config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>
): List<FormDto>? {
    val key = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, patient.delegations).firstOrNull()
        ?: throw IllegalArgumentException("No delegation for user")
    return this.findFormsByHCPartyPatientForeignKeys(user, hcPartyId, key, healthElementId, planOfActionId, formTemplateId, config)
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.findFormsByHCPartyPatientForeignKeys(
    user: UserDto,
    hcPartyId: String,
    secretFKeys: String,
    healthElementId: String?,
    planOfActionId: String?,
    formTemplateId: String?,
    config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>
): List<FormDto>? {
    return this.findFormsByHCPartyPatientForeignKeys(
        hcPartyId,
        secretFKeys,
        healthElementId,
        planOfActionId,
        formTemplateId
    )?.map { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.getForm(user: UserDto, formId: String, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>): FormDto? {
    return this.getForm(formId)?.let { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.modifyForm(user: UserDto, form: FormDto, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>): FormDto? {
    return this.modifyForm(
        config.encryptForm(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            form
        )
    )?.let { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.modifyForms(user: UserDto, form: List<FormDto>, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>): List<FormDto>? {
    return this.modifyForms(
        form.map {
            config.encryptForm(
                user.healthcarePartyId!!,
                (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
                it
            )
        }
    )?.map { config.decryptForm(user.healthcarePartyId!!, it) }
}


@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.createForms(user: UserDto, form: List<FormDto>, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>): List<FormDto>? {
    return this.createForms(
        form.map {
            config.encryptForm(
                user.healthcarePartyId!!,
                (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
                it
            )
        }
    )?.map { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.getChildrenForms(
    user: UserDto,
    formId: String,
    hcPartyId: String,
    config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>
): List<FormDto>? {
    return this.getChildrenForms(formId, hcPartyId)?.map { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.getFormByLogicalUuid(user: UserDto, logicalUuid: String, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>): FormDto? {
    return this.getFormByLogicalUuid(logicalUuid)?.let { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.getFormByUniqueId(user: UserDto, uniqueId: String, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>): FormDto? {
    return this.getFormByUniqueId(uniqueId)?.let { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.getForms(user: UserDto, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>): List<FormDto>? {
    return this.getForms(listOfIdsDto)?.map { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.getFormsByLogicalUuid(
    user: UserDto,
    logicalUuid: String,
    config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>
): List<FormDto>? {
    return this.getFormsByLogicalUuid(logicalUuid)?.map { config.decryptForm(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun FormApi.getFormsByUniqueId(user: UserDto, uniqueId: String, config: CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>): List<FormDto>? {
    return this.getFormsByUniqueId(uniqueId)?.map { config.decryptForm(user.healthcarePartyId!!, it) }
}


suspend fun CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>.encryptForm(
    myId: String,
    delegations: Set<String>,
    form: FormDto
): io.icure.kraken.client.models.FormDto {
    return if (form.encryptionKeys.any { (_, s) -> s.isNotEmpty() }) {
        form
    } else {
        val secret = UUID.randomUUID().toString()
        form.copy(encryptionKeys = (delegations + myId).fold(form.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptKeyForHcp(myId, d, form.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).keyFromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedForm, marshalledData) = this.marshaller(p)
        sanitizedForm.copy(
            encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key))
        )
    }
}

suspend fun CryptoConfig<FormDto, io.icure.kraken.client.models.FormDto>.decryptForm(myId: String, form: io.icure.kraken.client.models.FormDto): FormDto {
    val key = this.crypto.decryptEncryptionKeys(myId, form.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).keyFromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    return this.unmarshaller(form, decryptAES(data = Base64.getDecoder().decode(form.encryptedSelf), key = key))
}

@Mapper
interface FormMapper {
    fun map(form: FormDto): io.icure.kraken.client.models.FormDto
    fun map(form: io.icure.kraken.client.models.FormDto): FormDto
}

object FormMapperFactory {
    val instance = Mappers.getMapper(FormMapper::class.java)
}
