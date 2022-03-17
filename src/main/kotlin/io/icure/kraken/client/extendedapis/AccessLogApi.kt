package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.AccessLogApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.DelegationDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.AccessLogDto
import io.icure.kraken.client.models.decrypted.PaginatedListAccessLogDto
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
        responsible = user.dataOwnerId(),
        author = user.id,
        delegations = (delegations + user.dataOwnerId()).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    emptyList(), user.dataOwnerId(), d, config.crypto.encryptAESKeyForHcp(user.dataOwnerId(), d, this.id, sfk),
                ),
            ))
        },
        encryptionKeys = (delegations + user.dataOwnerId()).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    emptyList(), user.dataOwnerId(), d, config.crypto.encryptAESKeyForHcp(user.dataOwnerId(), d, this.id, ek),
                ),
            ))
        },
    )
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccessLogApi.createAccessLog(user: UserDto, accessLog: AccessLogDto, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) =
    this.createAccessLog(
        config.encryptAccessLog(
            user.dataOwnerId(),
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            accessLog
        )
    ).let { config.decryptAccessLog(user.dataOwnerId(), it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccessLogApi.findAccessLogsByUserAfterDate(user: UserDto, userId: String, accessType: String?, startDate: Long?, startKey: String?, startDocumentId: String?, limit: Int?, descending: Boolean?, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : PaginatedListAccessLogDto {
    return this.findAccessLogsByUserAfterDate(userId, accessType, startDate, startKey, startDocumentId, limit, descending).let {
        PaginatedListAccessLogDto(rows = it.rows.map { config.decryptAccessLog(user.dataOwnerId(), it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccessLogApi.listAccessLogsByHCPartyAndPatient(user: UserDto, hcPartyId: String, patient: PatientDto, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : List<AccessLogDto>? {
    val keys = config.crypto.decryptEncryptionKeys(user.dataOwnerId(), patient.delegations).takeIf { it.isNotEmpty() } ?: throw IllegalArgumentException("No delegation for user")
    return this.listAccessLogsByHCPartyAndPatientForeignKeys(hcPartyId, keys.joinToString(",")).map { config.decryptAccessLog(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccessLogApi.listAccessLogsByHCPartyAndPatientForeignKeys(user: UserDto, hcPartyId: String, secretFKeys: String, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : List<AccessLogDto>  {
    return this.listAccessLogsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys).map { config.decryptAccessLog(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccessLogApi.getAccessLog(user: UserDto, accessLogId: String, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>): AccessLogDto  {
    return this.getAccessLog(accessLogId).let { config.decryptAccessLog(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccessLogApi.findAccessLogsBy(user: UserDto, fromEpoch: Long?, toEpoch: Long?, startKey: Long?, startDocumentId: String?, limit: Int?, descending: Boolean?, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : PaginatedListAccessLogDto  {
    return this.findAccessLogsBy(fromEpoch, toEpoch, startKey, startDocumentId, limit, descending).let { paginatedList ->
        PaginatedListAccessLogDto(rows = paginatedList.rows.map { config.decryptAccessLog(user.dataOwnerId(), it) }, pageSize = paginatedList.pageSize, totalSize = paginatedList.totalSize, nextKeyPair = paginatedList.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun AccessLogApi.modifyAccessLog(user: UserDto, accessLog: AccessLogDto, config: CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>) : AccessLogDto  {
    return this.modifyAccessLog(
        config.encryptAccessLog(
            user.dataOwnerId(),
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            accessLog
        )
    ).let { config.decryptAccessLog(user.dataOwnerId(), it) }
}

suspend fun CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>.encryptAccessLog(myId: String, delegations: Set<String>, accessLog: AccessLogDto): io.icure.kraken.client.models.AccessLogDto {
    return if (accessLog.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        accessLog
    } else {
        val secret = UUID.randomUUID().toString()
        accessLog.copy(encryptionKeys = (delegations + myId).fold(accessLog.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(emptyList(), myId, d, this.crypto.encryptAESKeyForHcp(myId, d, accessLog.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.replace(
            "-",
            ""
        )?.keyFromHexString() ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedAccessLog, marshalledData) = this.marshaller(p)
        sanitizedAccessLog.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key)))
    }
}

suspend fun CryptoConfig<AccessLogDto, io.icure.kraken.client.models.AccessLogDto>.decryptAccessLog(myId: String, accessLog: io.icure.kraken.client.models.AccessLogDto): AccessLogDto {
    val key = this.crypto.decryptEncryptionKeys(myId, accessLog.encryptionKeys).firstOrNull()?.replace(
        "-",
        ""
    )?.keyFromHexString() ?: throw IllegalArgumentException("No encryption key for user")
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
