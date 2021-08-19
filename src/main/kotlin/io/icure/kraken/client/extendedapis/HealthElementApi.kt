package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.HelementApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.fromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.HealthElementDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun HealthElementDto.initDelegations(user: UserDto, config: CryptoConfig<HealthElementDto>): HealthElementDto {
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
suspend fun HelementApi.createHealthElement(user: UserDto, healthElement: HealthElementDto, config: CryptoConfig<HealthElementDto>) =
    this.createHealthElement(
        config.encryptHealthElement(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            healthElement
        )
    )?.let { config.decryptHealthElement(user.healthcarePartyId!!, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HelementApi.createHealthElements(user: UserDto, healthElements: List<HealthElementDto>, config: CryptoConfig<HealthElementDto>) : List<HealthElementDto>?  {
    return this.createHealthElements(
        healthElements.map {
            config.encryptHealthElement(
                user.healthcarePartyId!!,
                (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
                it
            )
        }
    )?.map { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HelementApi.newHealthElementDelegations(user: UserDto, healthElementId: String, delegationDto: List<DelegationDto>, config: CryptoConfig<HealthElementDto>) : HealthElementDto? {
    return this.newHealthElementDelegations(healthElementId, delegationDto)?.let { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HelementApi.findHealthElementsByHCPartyPatientForeignKeys(user: UserDto, hcPartyId: String, secretFKeys: String, config: CryptoConfig<HealthElementDto>) : List<HealthElementDto>? {
    return this.findHealthElementsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)?.map { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HelementApi.getHealthElement(user: UserDto, healthElementId: String, config: CryptoConfig<HealthElementDto>): HealthElementDto?  {
    return this.getHealthElement(healthElementId)?.let { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HelementApi.modifyHealthElement(user: UserDto, healthElement: HealthElementDto, config: CryptoConfig<HealthElementDto>) : HealthElementDto?  {
    return this.modifyHealthElement(
        config.encryptHealthElement(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            healthElement
        )
    )?.let { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HelementApi.modifyHealthElements(user: UserDto, healthElements: List<HealthElementDto>, config: CryptoConfig<HealthElementDto>) : List<HealthElementDto>?  {
    return this.modifyHealthElements(
        healthElements.map {
            config.encryptHealthElement(
                user.healthcarePartyId!!,
                (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
                it
            )
        }
    )?.map { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HelementApi.filterHealthElementsBy(user: UserDto, filterChainHealthElement: FilterChainHealthElement, config: CryptoConfig<HealthElementDto>) : List<HealthElementDto>? {
    return this.filterHealthElementsBy(filterChainHealthElement)?.map { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun HelementApi.setHealthElementsDelegations(user: UserDto, icureStubDtos: List<IcureStubDto>, config: CryptoConfig<HealthElementDto>) : List<HealthElementDto>? {
    return this.setHealthElementsDelegations(icureStubDtos)?.map { config.decryptHealthElement(user.healthcarePartyId!!, it) }
}


suspend fun CryptoConfig<HealthElementDto>.encryptHealthElement(myId: String, delegations: Set<String>, healthElement: HealthElementDto): io.icure.kraken.client.models.HealthElementDto {
    return if (healthElement.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        healthElement
    } else {
        val secret = UUID.randomUUID().toString()
        healthElement.copy(encryptionKeys = (delegations + myId).fold(healthElement.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptKeyForHcp(myId, d, healthElement.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).fromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedHealthElement, marshalledData) = this.marshaller(p)
        HealthElementMapperFactory.instance.map(sanitizedHealthElement.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key))))
    }
}

suspend fun CryptoConfig<HealthElementDto>.decryptHealthElement(myId: String, healthElement: io.icure.kraken.client.models.HealthElementDto): HealthElementDto = HealthElementMapperFactory.instance.map(healthElement).let { p ->
    val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).fromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    this.unmarshaller(p, decryptAES(data = Base64.getDecoder().decode(p.encryptedSelf), key = key))
}

@Mapper
interface HealthElementMapper {
    fun map(healthElement: HealthElementDto): io.icure.kraken.client.models.HealthElementDto
    fun map(healthElement: io.icure.kraken.client.models.HealthElementDto): HealthElementDto
}

object HealthElementMapperFactory {
    val instance = Mappers.getMapper(HealthElementMapper::class.java)
}
