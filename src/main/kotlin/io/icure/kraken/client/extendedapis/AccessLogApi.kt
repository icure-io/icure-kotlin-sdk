package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.AccesslogApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.PaginatedListAccessLogDto
import io.icure.kraken.client.models.decrypted.AccessLogDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun AccessLogDto.initDelegations(user: UserDto, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>): AccessLogDto {
    val delegations =  (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    val ek = UUID.randomUUID().toString()
    val sfk = UUID.randomUUID().toString()
    return this.copy(
        responsible = user.healthcarePartyId!!,
        author = user.id,
        delegations = (delegations + user.healthcarePartyId!!).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    listOf(), user.healthcarePartyId, d, config.crypto.encryptAESKeyForHcp(user.healthcarePartyId, d, this.id, sfk),
                ),
            ))
        },
        encryptionKeys = (delegations + user.healthcarePartyId!!).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    listOf(), user.healthcarePartyId, d, config.crypto.encryptAESKeyForHcp(user.healthcarePartyId, d, this.id, ek),
                ),
            ))
        },
    )
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccesslogApi.createAccessLog(user: UserDto, accessLog: AccessLogDto, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) =
    this.createAccessLog(
        config.encryptAccessLog(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            accessLog
        )
    )?.let { config.decryptAccessLog(user.healthcarePartyId!!, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccesslogApi.findByUserAfterDate(user: UserDto, userId: String, accessType: String?, startDate: Long?, startKey: String?, startDocumentId: String?, limit: Int?, descending: Boolean?, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : PaginatedListAccessLogDto? {
    return this.findByUserAfterDate(userId, accessType, startDate, startKey, startDocumentId, limit, descending)?.let {
        PaginatedListAccessLogDto(rows = it.rows?.map { config.decryptAccessLog(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccesslogApi.findByHCPartyPatient(user: UserDto, hcPartyId: String, patient: PatientDto, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : List<AccessLogDto>? {
    val key = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, patient.delegations).firstOrNull() ?: throw IllegalArgumentException("No delegation for user")
    return this.findAccessLogsByHCPartyPatientForeignKeys(hcPartyId, key)?.map { config.decryptAccessLog(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccesslogApi.findAccessLogsByHCPartyPatientForeignKeys(user: UserDto, hcPartyId: String, secretFKeys: String, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : List<AccessLogDto>?  {
    return this.findAccessLogsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)?.map { config.decryptAccessLog(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccesslogApi.getAccessLog(user: UserDto, accessLogId: String, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>): AccessLogDto?  {
    return this.getAccessLog(accessLogId)?.let { config.decryptAccessLog(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccesslogApi.listAccessLogs(user: UserDto, fromEpoch: Long?, toEpoch: Long?, startKey: Long?, startDocumentId: String?, limit: Int?, descending: Boolean?, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : PaginatedListAccessLogDto?  {
    return this.listAccessLogs(fromEpoch, toEpoch, startKey, startDocumentId, limit, descending)?.let {
        PaginatedListAccessLogDto(rows = it.rows?.map { config.decryptAccessLog(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccesslogApi.modifyAccessLog(user: UserDto, accessLog: AccessLogDto, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : AccessLogDto?  {
    return this.modifyAccessLog(
        config.encryptAccessLog(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            accessLog
        )
    )?.let { config.decryptAccessLog(user.healthcarePartyId!!, it) }
}

suspend fun CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>.encryptAccessLog(myId: String, delegations: Set<String>, accessLog: AccessLogDto): io.icure.kraken.client.models.AccessLogDto {
    return if (accessLog.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        accessLog
    } else {
        val secret = UUID.randomUUID().toString()
        accessLog.copy(encryptionKeys = (delegations + myId).fold(accessLog.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptAESKeyForHcp(myId, d, accessLog.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).keyFromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedAccessLog, marshalledData) = this.marshaller(p)
        sanitizedAccessLog.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key)))
    }
}

suspend fun CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>.decryptAccessLog(myId: String, accessLog: io.icure.kraken.client.models.AccessLogDto): AccessLogDto {
    val key = this.crypto.decryptEncryptionKeys(myId, accessLog.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).keyFromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    return this.unmarshaller(accessLog, decryptAES(data = Base64.getDecoder().decode(accessLog.encryptedSelf), key = key))
}

@Mapper
interface AccessLogMapper {
    fun map(accessLog: AccessLogDto): io.icure.kraken.client.models.AccessLogDto
    fun map(accessLog: io.icure.kraken.client.models.AccessLogDto): AccessLogDto
}

object AccessLogMapperFactory {
    val instance = Mappers.getMapper(AccessLogMapper::class.java)
}
