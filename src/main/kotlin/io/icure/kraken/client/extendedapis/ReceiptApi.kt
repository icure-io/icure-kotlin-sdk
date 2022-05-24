package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.ReceiptApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.ReceiptDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.nio.ByteBuffer
import java.util.*

suspend fun ReceiptDto.initDelegations(user: UserDto, config: CryptoConfig<ReceiptDto, io.icure.kraken.client.models.ReceiptDto>): ReceiptDto {
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
suspend fun ReceiptApi.createReceipt(user: UserDto, receipt: ReceiptDto, config: CryptoConfig<ReceiptDto, io.icure.kraken.client.models.ReceiptDto>) =
    this.createReceipt(
        config.encryptReceipt(
            user.dataOwnerId(),
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            receipt
        )
    ).let { config.decryptReceipt(user.dataOwnerId(), it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ReceiptApi.getReceipt(user: UserDto, receiptId: String, config: CryptoConfig<ReceiptDto, io.icure.kraken.client.models.ReceiptDto>): ReceiptDto  {
    return this.getReceipt(receiptId).let { config.decryptReceipt(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ReceiptApi.modifyReceipt(user: UserDto, receipt: ReceiptDto, config: CryptoConfig<ReceiptDto, io.icure.kraken.client.models.ReceiptDto>) : ReceiptDto  {
    return this.modifyReceipt(
        config.encryptReceipt(
            user.dataOwnerId(),
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            receipt
        )
    ).let { config.decryptReceipt(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ReceiptApi.listByReference(user: UserDto, ref: String, config: CryptoConfig<ReceiptDto, io.icure.kraken.client.models.ReceiptDto>) : List<ReceiptDto>  {
    return this.listByReference(ref).map { config.decryptReceipt(user.dataOwnerId(), it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ReceiptApi.setReceiptAttachment(user: UserDto, receiptId: String, blobType: String, requestBody: Flow<ByteBuffer>, enckeys: String?, config: CryptoConfig<ReceiptDto, io.icure.kraken.client.models.ReceiptDto>) :ReceiptDto  {
    return this.setReceiptAttachment(receiptId, blobType, requestBody, enckeys).let { config.decryptReceipt(user.dataOwnerId(), it) }
}

suspend fun CryptoConfig<ReceiptDto, io.icure.kraken.client.models.ReceiptDto>.encryptReceipt(myId: String, delegations: Set<String>, receipt: ReceiptDto): io.icure.kraken.client.models.ReceiptDto {
    return if (receipt.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        receipt
    } else {
        val secret = UUID.randomUUID().toString()
        receipt.copy(encryptionKeys = (delegations + myId).fold(receipt.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(emptyList(), myId, d, this.crypto.encryptAESKeyForDataOwner(myId, d, receipt.id, secret).first)))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.replace(
            "-",
            ""
        )?.keyFromHexString() ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedReceipt, marshalledData) = this.marshaller(p)
        sanitizedReceipt.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key)))
    }
}

suspend fun CryptoConfig<ReceiptDto, io.icure.kraken.client.models.ReceiptDto>.decryptReceipt(myId: String, receipt: io.icure.kraken.client.models.ReceiptDto): ReceiptDto {
    val key = this.crypto.decryptEncryptionKeys(myId, receipt.encryptionKeys).firstOrNull()?.replace(
        "-",
        ""
    )?.keyFromHexString() ?: throw IllegalArgumentException("No encryption key for user")
    return this.unmarshaller(receipt, decryptAES(data = Base64.getDecoder().decode(receipt.encryptedSelf), key = key))
}

@Mapper
interface ReceiptMapper {
    fun map(receipt: ReceiptDto): io.icure.kraken.client.models.ReceiptDto
    fun map(receipt: io.icure.kraken.client.models.ReceiptDto): ReceiptDto
}

object ReceiptMapperFactory {
    val instance = Mappers.getMapper(ReceiptMapper::class.java)
}
