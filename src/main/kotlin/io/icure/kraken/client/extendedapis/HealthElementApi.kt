package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.HealthElementApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.HealthElementDto
import io.icure.kraken.client.models.decrypted.PaginatedListHealthElementDto
import io.icure.kraken.client.models.filter.chain.FilterChain
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun HealthElementDto.initDelegations(user: UserDto, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>): HealthElementDto {
    val delegations =  (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    val ek = UUID.randomUUID().toString()
    val sfk = UUID.randomUUID().toString()
    return this.copy(
        responsible = user.healthcarePartyId!!,
        author = user.id,
        delegations = (delegations + user.healthcarePartyId).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    emptyList(), user.healthcarePartyId, d, config.crypto.encryptAESKeyForHcp(user.healthcarePartyId, d, this.id, sfk),
                ),
            ))
        },
        encryptionKeys = (delegations + user.healthcarePartyId).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    emptyList(), user.healthcarePartyId, d, config.crypto.encryptAESKeyForHcp(user.healthcarePartyId, d, this.id, ek),
                ),
            ))
        },
    )
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.createHealthElement(user: UserDto, healthElement: HealthElementDto, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>) =
    this.createHealthElement(
        config.encryptHealthElement(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            healthElement
        )
    ).let { config.decryptHealthElement(user.healthcarePartyId, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.createHealthElements(user: UserDto, patient: io.icure.kraken.client.models.decrypted.PatientDto, healthElements: List<HealthElementDto>, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>) : List<HealthElementDto>  {
    val key = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, patient.delegations).firstOrNull() ?: throw IllegalArgumentException("No delegation for user")
    val delegations =  (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    return this.createHealthElements(
        healthElements.map {
            config.encryptHealthElement(
                user.healthcarePartyId,
                (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
                it
            ).let { ec ->
                ec.copy(
                    secretForeignKeys = listOf(key),
                    cryptedForeignKeys = (delegations + user.healthcarePartyId).fold(ec.cryptedForeignKeys) { m, d ->
                        m + (d to setOf(
                            DelegationDto(
                                emptyList(),
                                user.healthcarePartyId,
                                d,
                                config.crypto.encryptValueForHcp(user.healthcarePartyId, d, ec.id, patient.id),
                            ),
                        ))
                    },
                )
            }
        }
    ).map { config.decryptHealthElement(user.healthcarePartyId, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.createHealthElement(user: UserDto, patient: io.icure.kraken.client.models.decrypted.PatientDto, healthElement: HealthElementDto, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>): HealthElementDto {
    val key = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, patient.delegations).firstOrNull() ?: throw IllegalArgumentException("No delegation for user")
    val delegations =  (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    return this.createHealthElement(
        config.encryptHealthElement(
            user.healthcarePartyId,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            healthElement.initDelegations(user, config)
        ).let { ec ->
            ec.copy(
                secretForeignKeys = listOf(key),
                cryptedForeignKeys = (delegations + user.healthcarePartyId).fold(ec.cryptedForeignKeys) { m, d ->
                    m + (d to setOf(
                        DelegationDto(
                            emptyList(),
                            user.healthcarePartyId,
                            d,
                            config.crypto.encryptValueForHcp(user.healthcarePartyId, d, ec.id, patient.id),
                        ),
                    ))
                },
            )
        }
    ).let { config.decryptHealthElement(user.healthcarePartyId, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.newHealthElementDelegations(user: UserDto, healthElementId: String, delegationDto: List<DelegationDto>, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>) : HealthElementDto {
    return this.newHealthElementDelegations(healthElementId, delegationDto).let { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.listHealthElementsByHCPartyAndPatient(user: UserDto, hcPartyId: String, patient: PatientDto, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>) : List<HealthElementDto> {
    val keys = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, patient.delegations).takeIf { it.isNotEmpty() }
        ?: throw IllegalArgumentException("No delegation for user")
    return this.listHealthElementsByHCPartyAndPatientForeignKeys(user, hcPartyId, keys.joinToString(","), config)
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.listHealthElementsByHCPartyAndPatientForeignKeys(user: UserDto, hcPartyId: String, secretFKeys: String, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>) : List<HealthElementDto> {
    return this.listHealthElementsByHCPartyAndPatientForeignKeys(hcPartyId, secretFKeys).map { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.getHealthElement(user: UserDto, healthElementId: String, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>): HealthElementDto  {
    return this.getHealthElement(healthElementId).let { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.getHealthElements(user: UserDto, healthElementIds: ListOfIdsDto, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>): List<HealthElementDto>  {
    return this.getHealthElements(healthElementIds).map { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.modifyHealthElement(user: UserDto, healthElement: HealthElementDto, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>) : HealthElementDto  {
    return this.modifyHealthElement(
        config.encryptHealthElement(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            healthElement
        )
    ).let { config.decryptHealthElement(user.healthcarePartyId, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.modifyHealthElements(user: UserDto, healthElements: List<HealthElementDto>, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>) : List<HealthElementDto>  {
    return this.modifyHealthElements(
        healthElements.map {
            config.encryptHealthElement(
                user.healthcarePartyId!!,
                (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
                it
            )
        }
    ).map { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.filterHealthElementsBy(
    user: UserDto,
    filterChainHealthElement: FilterChain<io.icure.kraken.client.models.HealthElementDto>,
    config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>,
    startDocumentId: String?,
    limit: Int?
): PaginatedListHealthElementDto {
    return this.filterHealthElementsBy(filterChainHealthElement, startDocumentId, limit)
        .let { paginatedListHealthElementDto ->
            PaginatedListHealthElementDto(
                rows = paginatedListHealthElementDto.rows.map { healthElementDto ->
                    config.decryptHealthElement(
                        user.healthcarePartyId!!,
                        healthElementDto
                    )
                },
                pageSize = paginatedListHealthElementDto.pageSize,
                totalSize = paginatedListHealthElementDto.totalSize,
                nextKeyPair = paginatedListHealthElementDto.nextKeyPair
            )
        }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HealthElementApi.setHealthElementsDelegations(user: UserDto, icureStubDtos: List<IcureStubDto>, config: CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>) : List<HealthElementDto> {
    return this.setHealthElementsDelegations(icureStubDtos).map { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}


suspend fun CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>.encryptHealthElement(myId: String, delegations: Set<String>, healthElement: HealthElementDto): io.icure.kraken.client.models.HealthElementDto {
    return if (healthElement.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        healthElement
    } else {
        val secret = UUID.randomUUID().toString()
        healthElement.copy(encryptionKeys = (delegations + myId).fold(healthElement.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(emptyList(), myId, d, this.crypto.encryptAESKeyForHcp(myId, d, healthElement.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.replace(
            "-",
            ""
        )?.keyFromHexString() ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedHealthElement, marshalledData) = this.marshaller(p)
        sanitizedHealthElement.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key)))
    }
}

suspend fun CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>.decryptHealthElement(myId: String, healthElement: io.icure.kraken.client.models.HealthElementDto): HealthElementDto {
    val key = this.crypto.decryptEncryptionKeys(myId, healthElement.encryptionKeys).firstOrNull()?.replace(
        "-",
        ""
    )?.keyFromHexString() ?: throw IllegalArgumentException("No encryption key for user")
    return this.unmarshaller(healthElement, decryptAES(data = Base64.getDecoder().decode(healthElement.encryptedSelf), key = key))
}

@Mapper
interface HealthElementMapper {
    fun map(healthElement: HealthElementDto): io.icure.kraken.client.models.HealthElementDto
    fun map(healthElement: io.icure.kraken.client.models.HealthElementDto): HealthElementDto
}

object HealthElementMapperFactory {
    val instance = Mappers.getMapper(HealthElementMapper::class.java)
}
