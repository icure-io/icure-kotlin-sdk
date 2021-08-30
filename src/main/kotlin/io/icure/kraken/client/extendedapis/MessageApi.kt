package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.MessageApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.fromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.MessageDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun MessageDto.initDelegations(user: UserDto, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>): MessageDto {
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
suspend fun MessageApi.createMessage(user: UserDto, message: MessageDto, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) =
    this.createMessage(
        config.encryptMessage(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            message
        )
    )?.let { config.decryptMessage(user.healthcarePartyId!!, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.getMessage(user: UserDto, messageId: String, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>): MessageDto?  {
    return this.getMessage(messageId)?.let { config.decryptMessage(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.modifyMessage(user: UserDto, message: MessageDto, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : MessageDto?  {
    return this.modifyMessage(
        config.encryptMessage(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            message
        )
    )?.let { config.decryptMessage(user.healthcarePartyId!!, it) }
}


@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.deleteDelegation(user: UserDto, messageId: String, delegateId: String, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : MessageDto?  {
    return this.deleteDelegation(messageId, delegateId)?.let { config.decryptMessage(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.findMessages(user: UserDto, startKey: String?, startDocumentId: String?, limit: Int?, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : io.icure.kraken.client.models.decrypted.PaginatedListMessageDto?  {
    return this.findMessages(startKey, startDocumentId, limit)?.let {
        io.icure.kraken.client.models.decrypted.PaginatedListMessageDto(
            pageSize = it.pageSize,
            totalSize = it.totalSize,
            rows = it.rows.map { config.decryptMessage(user.healthcarePartyId!!, it) },
            nextKeyPair = it.nextKeyPair
        )
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.findMessagesByFromAddress(user: UserDto, fromAddress: String?, startKey: String?, startDocumentId: String?, limit: Int?, hcpId: String?, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : io.icure.kraken.client.models.decrypted.PaginatedListMessageDto?  {
    return this.findMessagesByFromAddress(fromAddress, startKey, startDocumentId, limit, hcpId)?.let {
        io.icure.kraken.client.models.decrypted.PaginatedListMessageDto(
            pageSize = it.pageSize,
            totalSize = it.totalSize,
            rows = it.rows.map { config.decryptMessage(user.healthcarePartyId!!, it) },
            nextKeyPair = it.nextKeyPair
        )
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.findMessagesByHCPartyPatientForeignKeys(user: UserDto, secretFKeys: String, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : List<MessageDto>?  {
    return this.findMessagesByHCPartyPatientForeignKeys(secretFKeys)?.map { config.decryptMessage(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.findMessagesByToAddress(user: UserDto, toAddress: String?, startKey: String?, startDocumentId: String?, limit: Int?, reverse: Boolean?, hcpId: String?, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : io.icure.kraken.client.models.decrypted.PaginatedListMessageDto?  {
    return this.findMessagesByToAddress(toAddress, startKey, startDocumentId, limit, reverse, hcpId)?.let {
        io.icure.kraken.client.models.decrypted.PaginatedListMessageDto(
            pageSize = it.pageSize,
            totalSize = it.totalSize,
            rows = it.rows.map { config.decryptMessage(user.healthcarePartyId!!, it) },
            nextKeyPair = it.nextKeyPair
        )
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.findMessagesByTransportGuid(user: UserDto, transportGuid: String?, received: Boolean?, startKey: String?, startDocumentId: String?, limit: Int?, hcpId: String?, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : io.icure.kraken.client.models.decrypted.PaginatedListMessageDto?  {
    return this.findMessagesByTransportGuid(transportGuid, received, startKey, startDocumentId, limit, hcpId)?.let {
        io.icure.kraken.client.models.decrypted.PaginatedListMessageDto(
            pageSize = it.pageSize,
            totalSize = it.totalSize,
            rows = it.rows.map { config.decryptMessage(user.healthcarePartyId!!, it) },
            nextKeyPair = it.nextKeyPair
        )
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.findMessagesByTransportGuidSentDate(user: UserDto, from: Long?, to: Long?, transportGuid: String?, startKey: String?, startDocumentId: String?, limit: Int?, hcpId: String?, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : io.icure.kraken.client.models.decrypted.PaginatedListMessageDto?  {
    return this.findMessagesByTransportGuidSentDate(from, to, transportGuid, startKey, startDocumentId, limit, hcpId)?.let {
        io.icure.kraken.client.models.decrypted.PaginatedListMessageDto(
            pageSize = it.pageSize,
            totalSize = it.totalSize,
            rows = it.rows.map { config.decryptMessage(user.healthcarePartyId!!, it) },
            nextKeyPair = it.nextKeyPair
        )
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.getChildrenMessages(user: UserDto, messageId: String, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : List<MessageDto>?  {
    return this.getChildrenMessages(messageId)?.map { config.decryptMessage(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.getChildrenMessagesOfList(user: UserDto, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : List<MessageDto>?  {
    return this.getChildrenMessagesOfList(listOfIdsDto)?.map { config.decryptMessage(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.listMessagesByInvoiceIds(user: UserDto, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : List<MessageDto>?  {
    return this.listMessagesByInvoiceIds(listOfIdsDto)?.map { config.decryptMessage(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.listMessagesByTransportGuids(user: UserDto, hcpId: String, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : List<MessageDto>?  {
    return this.listMessagesByTransportGuids(hcpId, listOfIdsDto)?.map { config.decryptMessage(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.setMessagesReadStatus(user: UserDto, messagesReadStatusUpdate: MessagesReadStatusUpdate, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : List<MessageDto>?  {
    return this.setMessagesReadStatus(messagesReadStatusUpdate)?.map { config.decryptMessage(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MessageApi.setMessagesStatusBits(user: UserDto, status: Int, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>) : List<MessageDto>?  {
    return this.setMessagesStatusBits(status, listOfIdsDto)?.map { config.decryptMessage(user.healthcarePartyId!!, it) }
}



suspend fun CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>.encryptMessage(myId: String, delegations: Set<String>, message: MessageDto): io.icure.kraken.client.models.MessageDto {
    return if (message.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        message
    } else {
        val secret = UUID.randomUUID().toString()
        message.copy(encryptionKeys = (delegations + myId).fold(message.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptKeyForHcp(myId, d, message.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).fromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedMessage, marshalledData) = this.marshaller(p)
        sanitizedMessage.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key)))
    }
}

suspend fun CryptoConfig<MessageDto, io.icure.kraken.client.models.MessageDto>.decryptMessage(myId: String, message: io.icure.kraken.client.models.MessageDto): MessageDto {
    val key = this.crypto.decryptEncryptionKeys(myId, message.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).fromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    return this.unmarshaller(message, decryptAES(data = Base64.getDecoder().decode(message.encryptedSelf), key = key))
}

@Mapper
interface MessageMapper {
    fun map(message: MessageDto): io.icure.kraken.client.models.MessageDto
    fun map(message: io.icure.kraken.client.models.MessageDto): MessageDto
}

object MessageMapperFactory {
    val instance = Mappers.getMapper(MessageMapper::class.java)
}
