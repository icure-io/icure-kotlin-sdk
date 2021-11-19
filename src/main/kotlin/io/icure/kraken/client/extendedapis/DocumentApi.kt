package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.DocumentApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.DocumentDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.nio.ByteBuffer
import java.util.*

suspend fun DocumentDto.initDelegations(user: UserDto, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>): DocumentDto {
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
suspend fun DocumentApi.createDocument(user: UserDto, document: DocumentDto, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) =
    this.createDocument(
        config.encryptDocument(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            document
        )
    )?.let { config.decryptDocument(user.healthcarePartyId!!, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.findDocumentsByHCPartyPatient(user: UserDto, hcPartyId: String, patient: PatientDto, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) : List<DocumentDto>? {
    val key = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, patient.delegations).firstOrNull()
        ?: throw IllegalArgumentException("No delegation for user")
    return this.findDocumentsByHCPartyPatientForeignKeys(user, hcPartyId, key, config)
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.findByTypeHCPartyMessage(user: UserDto, documentTypeCode: String, hcPartyId: String, message: MessageDto, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) : List<DocumentDto>? {
    val key = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, message.delegations).firstOrNull()
        ?: throw IllegalArgumentException("No delegation for user")
    return this.findByTypeHCPartyMessageSecretFKeys(documentTypeCode, hcPartyId, key)?.map { config.decryptDocument(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.findDocumentsByHCPartyPatientForeignKeys(user: UserDto, hcPartyId: String, secretFKeys: String, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) : List<DocumentDto>? {
    return this.findDocumentsByHCPartyPatientForeignKeys(hcPartyId, secretFKeys)?.map { config.decryptDocument(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.findByTypeHCPartyMessageSecretFKeys(user: UserDto, documentTypeCode: String, hcPartyId: String, secretFKeys: String, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) : List<DocumentDto>? {
    return this.findByTypeHCPartyMessageSecretFKeys(documentTypeCode, hcPartyId, secretFKeys)?.map { config.decryptDocument(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.findWithoutDelegation(user: UserDto, limit: Int?, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) : List<DocumentDto>? {
    return this.findWithoutDelegation(limit)?.map { config.decryptDocument(user.healthcarePartyId!!, it) }
}


@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.getDocument(user: UserDto, documentId: String, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>): DocumentDto?  {
    return this.getDocument(documentId)?.let { config.decryptDocument(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.modifyDocument(user: UserDto, document: DocumentDto, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) : DocumentDto?  {
    return this.modifyDocument(
        config.encryptDocument(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            document
        )
    )?.let { config.decryptDocument(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.modifyDocuments(user: UserDto, documents: List<DocumentDto>, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) : List<DocumentDto>?  {
    return this.modifyDocuments(documents.map {
        config.encryptDocument(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            it
        )
    })?.map { config.decryptDocument(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.deleteAttachment(user: UserDto, documentId: String, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) : DocumentDto? {
    return this.deleteAttachment(documentId)?.let { config.decryptDocument(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.setDocumentAttachment(user: UserDto, documentId: String, requestBody: Flow<ByteBuffer>, enckeys: String?, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>) : DocumentDto? {
    return this.setDocumentAttachment(documentId, requestBody, enckeys)?.let { config.decryptDocument(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.getDocumentsByExternalUuid(user: UserDto, externalUuid: String, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>): List<DocumentDto>?  {
    return this.getDocumentsByExternalUuid(externalUuid)?.map { config.decryptDocument(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun DocumentApi.getDocuments(user: UserDto, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>): List<DocumentDto>?  {
    return this.getDocuments(listOfIdsDto)?.map { config.decryptDocument(user.healthcarePartyId!!, it) }
}

suspend fun CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>.encryptDocument(myId: String, delegations: Set<String>, document: DocumentDto): io.icure.kraken.client.models.DocumentDto {
    return if (document.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        document
    } else {
        val secret = UUID.randomUUID().toString()
        document.copy(encryptionKeys = (delegations + myId).fold(document.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptAESKeyForHcp(myId, d, document.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).keyFromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedDocument, marshalledData) = this.marshaller(p)
        sanitizedDocument.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key)))
    }
}

suspend fun CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>.decryptDocument(myId: String, document: io.icure.kraken.client.models.DocumentDto): DocumentDto {
    val key = this.crypto.decryptEncryptionKeys(myId, document.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).keyFromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    return this.unmarshaller(document, decryptAES(data = Base64.getDecoder().decode(document.encryptedSelf), key = key))
}

@Mapper
interface DocumentMapper {
    fun map(document: DocumentDto): io.icure.kraken.client.models.DocumentDto
    fun map(document: io.icure.kraken.client.models.DocumentDto): DocumentDto
}

object DocumentMapperFactory {
    val instance = Mappers.getMapper(DocumentMapper::class.java)
}
