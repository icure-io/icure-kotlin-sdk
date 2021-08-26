package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.ReceiptApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.fromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.ReceiptDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun ReceiptDto.initDelegations(user: UserDto, config: CryptoConfig<ReceiptDto>): ReceiptDto {
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
suspend fun ReceiptApi.createReceipt(user: UserDto, receipt: ReceiptDto, config: CryptoConfig<ReceiptDto>) =
    this.createReceipt(
        config.encryptReceipt(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            receipt
        )
    )?.let { config.decryptReceipt(user.healthcarePartyId!!, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ReceiptApi.getReceipt(user: UserDto, receiptId: String, config: CryptoConfig<ReceiptDto>): ReceiptDto?  {
    return this.getReceipt(receiptId)?.let { config.decryptReceipt(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ReceiptApi.modifyReceipt(user: UserDto, receipt: ReceiptDto, config: CryptoConfig<ReceiptDto>) : ReceiptDto?  {
    return this.modifyReceipt(
        config.encryptReceipt(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            receipt
        )
    )?.let { config.decryptReceipt(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ReceiptApi.listByReference(user: UserDto, ref: String, config: CryptoConfig<ReceiptDto>) : List<ReceiptDto>?  {
    return this.listByReference(ref)?.map { config.decryptReceipt(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ReceiptApi.setReceiptAttachment(user: UserDto, receiptId: String, blobType: String, requestBody: ByteArray, enckeys: String?, config: CryptoConfig<ReceiptDto>) :ReceiptDto?  {
    return this.setReceiptAttachment(receiptId, blobType, requestBody, enckeys)?.let { config.decryptReceipt(user.healthcarePartyId!!, it) }
}

suspend fun CryptoConfig<ReceiptDto>.encryptReceipt(myId: String, delegations: Set<String>, receipt: ReceiptDto): io.icure.kraken.client.models.ReceiptDto {
    return if (receipt.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        receipt
    } else {
        val secret = UUID.randomUUID().toString()
        receipt.copy(encryptionKeys = (delegations + myId).fold(receipt.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptKeyForHcp(myId, d, receipt.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).fromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedReceipt, marshalledData) = this.marshaller(p)
        ReceiptMapperFactory.instance.map(sanitizedReceipt.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key))))
    }
}

suspend fun CryptoConfig<ReceiptDto>.decryptReceipt(myId: String, receipt: io.icure.kraken.client.models.ReceiptDto): ReceiptDto = ReceiptMapperFactory.instance.map(receipt).let { p ->
    val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).fromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    this.unmarshaller(p, decryptAES(data = Base64.getDecoder().decode(p.encryptedSelf), key = key))
}

@Mapper
interface ReceiptMapper {
    fun map(receipt: ReceiptDto): io.icure.kraken.client.models.ReceiptDto
    fun map(receipt: io.icure.kraken.client.models.ReceiptDto): ReceiptDto
}

object ReceiptMapperFactory {
    val instance = Mappers.getMapper(ReceiptMapper::class.java)
}
