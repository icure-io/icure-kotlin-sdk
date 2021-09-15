package io.icure.kraken.client.extendedapis

import com.fasterxml.jackson.databind.ObjectMapper
import io.icure.kraken.client.apis.ContactApi
import io.icure.kraken.client.crypto.Crypto
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.fromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.ContactDto
import io.icure.kraken.client.models.decrypted.PaginatedListContactDto
import io.icure.kraken.client.models.decrypted.PatientDto
import io.icure.kraken.client.models.decrypted.ServiceDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun ContactDto.initDelegations(user: UserDto, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>): ContactDto {
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
suspend fun ContactApi.createContact(user: UserDto, contact: ContactDto, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) =
    this.createContact(
        config.encryptContact(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            contact
        )
    )?.let { config.decryptContact(user.healthcarePartyId!!, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.createContact(user: UserDto, patient:PatientDto, contact: ContactDto, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>): ContactDto? {
    val key = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, patient.delegations).firstOrNull() ?: throw IllegalArgumentException("No delegation for user")
    val delegations =  (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    return this.createContact(
        config.encryptContact(
            user.healthcarePartyId,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            contact
        ).let { ec ->
            ec.copy(
                secretForeignKeys = listOf(key),
                cryptedForeignKeys = (delegations + user.healthcarePartyId!!).fold(ec.cryptedForeignKeys) { m, d ->
                    m + (d to setOf(
                        DelegationDto(
                            listOf(),
                            user.healthcarePartyId,
                            d,
                            config.crypto.encryptKeyForHcp(user.healthcarePartyId, d, ec.id, patient.id),
                        ),
                    ))
                },
            )
        }
    )?.let { config.decryptContact(user.healthcarePartyId, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.modifyContact(user: UserDto, contact: ContactDto, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) =
    this.modifyContact(
        config.encryptContact(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            contact
        )
    )?.let { config.decryptContact(user.healthcarePartyId!!, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.createContacts(user: UserDto, contactDto: List<ContactDto>, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    return this.createContacts(contactDto.map { config.encryptContact(
        user.healthcarePartyId!!,
        (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
        it
    ) })?.map { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.modifyContacts(user: UserDto, contactDto: List<ContactDto>, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    return this.modifyContacts(contactDto.map { config.encryptContact(
        user.healthcarePartyId!!,
        (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
        it
    ) })?.map { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.filterContactsBy(user: UserDto, filterChainContact: FilterChainContact, startKey: String?, startDocumentId: String?, limit: Int?, skip: Int?, sort: String?, desc: Boolean?, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : PaginatedListContactDto? {
    return this.filterContactsBy(filterChainContact, startDocumentId, limit)?.let {
        PaginatedListContactDto(rows = it.rows?.map { config.decryptContact(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.getContact(user: UserDto, contactId: String, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : ContactDto? {
    return this.getContact(contactId)?.let { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.getContacts(user: UserDto, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    return this.getContacts(listOfIdsDto)?.map { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.filterServicesBy(user: UserDto, filterChainService: FilterChainService, startDocumentId: String?, limit: Int?, crypto: Crypto) : io.icure.kraken.client.models.decrypted.PaginatedListServiceDto? {
    return this.filterServicesBy(filterChainService, startDocumentId, limit)?.let {
        io.icure.kraken.client.models.decrypted.PaginatedListServiceDto(rows = it.rows?.let { crypto.decryptServices(user.healthcarePartyId!!, null, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }

}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.findByHCPartyFormId(user: UserDto, hcPartyId: String, formId: String, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    return this.findByHCPartyFormId(hcPartyId, formId)?.map { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.findByHCPartyFormIds(user: UserDto, hcPartyId: String, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    return this.findByHCPartyFormIds(hcPartyId, listOfIdsDto)?.map { config.decryptContact(user.healthcarePartyId!!, it) }

}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.findByHCPartyPatient(user: UserDto, hcPartyId: String, patient: PatientDto, planOfActionsIds: String?, skipClosedContacts: Boolean?, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    val key = config.crypto.decryptEncryptionKeys(user.healthcarePartyId!!, patient.delegations).firstOrNull() ?: throw IllegalArgumentException("No delegation for user")
    return this.findByHCPartyPatientSecretFKeys(hcPartyId, key, planOfActionsIds, skipClosedContacts)?.map { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.findByHCPartyServiceId(user: UserDto, hcPartyId: String, serviceId: String, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    return this.findByHCPartyServiceId(hcPartyId, serviceId)?.map { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.findContactsByExternalId(user: UserDto, externalId: String, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    return this.findContactsByExternalId(externalId)?.map { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.findContactsByHCPartyPatientForeignKeys(user: UserDto, hcPartyId: String, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    return this.findContactsByHCPartyPatientForeignKeys(hcPartyId, listOfIdsDto)?.map { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.listContactsByOpeningDate(user: UserDto, startKey: Long, endKey: Long, hcpartyid: String, startDocumentId: String?, limit: Int?, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : PaginatedListContactDto? {
    return this.listContactsByOpeningDate(startKey, endKey, hcpartyid, startDocumentId, limit)?.let {
        PaginatedListContactDto(rows = it.rows?.map { config.decryptContact(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }

}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.listServices(user: UserDto, listOfIdsDto: ListOfIdsDto, crypto: Crypto) : List<ServiceDto>? {
    return this.listServices(listOfIdsDto)?.let { crypto.decryptServices(user.healthcarePartyId!!, null, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.listServicesByAssociationId(user: UserDto, associationId: String, crypto: Crypto) : List<ServiceDto>? {
    return this.listServicesByAssociationId(associationId)?.let { crypto.decryptServices(user.healthcarePartyId!!, null, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.listServicesLinkedTo(user: UserDto, listOfIdsDto: ListOfIdsDto, linkType: String?, crypto: Crypto) : List<ServiceDto>? {
    return this.listServicesLinkedTo(listOfIdsDto, linkType)?.let { crypto.decryptServices(user.healthcarePartyId!!, null, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.newContactDelegations(user: UserDto, contactId: String, delegationDto: DelegationDto, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : ContactDto? {
    return this.newContactDelegations(contactId, delegationDto)?.let { config.decryptContact(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun ContactApi.setContactsDelegations(user: UserDto, icureStubDto: List<IcureStubDto>, config: CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>) : List<ContactDto>? {
    return this.setContactsDelegations(icureStubDto)?.map { config.decryptContact(user.healthcarePartyId!!, it) }
}

suspend fun CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>.encryptContact(myId: String, delegations: Set<String>, contact: ContactDto): io.icure.kraken.client.models.ContactDto {
    return if (contact.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        contact
    } else {
        val secret = UUID.randomUUID().toString()
        contact.copy(encryptionKeys = (delegations + myId).fold(contact.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptKeyForHcp(myId, d, contact.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).fromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedContact, marshalledData) = this.marshaller(p)
        sanitizedContact.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key)))
    }
}

suspend fun CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>.decryptContact(
    myId: String,
    contact: io.icure.kraken.client.models.ContactDto
): ContactDto {
    val key = this.crypto.decryptEncryptionKeys(myId, contact.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).fromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    return this.unmarshaller(contact, decryptAES(data = Base64.getDecoder().decode(contact.encryptedSelf), key = key))
}

suspend fun Crypto.encryptServices(myId: String, delegations: Set<String>, contactKey: ByteArray?, services: List<ServiceDto>): List<io.icure.kraken.client.models.ServiceDto> {
    val objectMapper = ObjectMapper()

    return services.map { s ->
        val key = contactKey ?: this.decryptEncryptionKeys(myId, s.encryptionKeys).firstOrNull()?.let { aesKey ->
            aesKey.replace(
                "-",
                ""
            ).fromHexString()
        } ?: throw IllegalArgumentException("No encryption key for user")
        if (s.content.all { (_,c) ->
            c.compoundValue != null && c.stringValue == null && c.documentId == null  && c.measureValue == null  && c.medicationValue == null  &&
                c.booleanValue == null && c.numberValue == null && c.instantValue == null  && c.fuzzyDateValue == null  && c.binaryValue == null
        }) {
            ServiceMapperFactory.instance.map(s).copy(content = s.content.mapValues { (_,c) -> ContentDto(compoundValue = c.compoundValue?.let { this.encryptServices(myId, delegations, contactKey, it) }) })
        } else {
            ServiceMapperFactory.instance.map(s.copy(content = mapOf(), encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = objectMapper.writeValueAsBytes(mapOf("content" to s.content)), key = key))))
        }
    }
}

suspend fun Crypto.decryptServices(myId: String, contactKey: ByteArray?, services: List<io.icure.kraken.client.models.ServiceDto>): List<ServiceDto> = services?.map { s ->
    val objectMapper = ObjectMapper()
    val key = contactKey ?: this.decryptEncryptionKeys(myId, s.encryptionKeys).firstOrNull()?.let { aesKey ->
        aesKey.replace(
            "-",
            ""
        ).fromHexString()
    } ?: throw IllegalArgumentException("No encryption key for user")
    s.encryptedSelf?.let { es ->
        ServiceMapperFactory.instance.map(s).copy(content = objectMapper.readValue(decryptAES(data = Base64.getDecoder().decode(es), key = key), ContentWrapper::class.java).content)
    } ?: ServiceMapperFactory.instance.map(s).let { ss -> ss.copy(content = ss.content.mapValues { (_,c) -> c.copy(compoundValue = c.compoundValue?.let { this.decryptServices(myId, contactKey, it.map { ServiceMapperFactory.instance.map(it) }) }) }) }
}
data class ContentWrapper(val content: Map<String, io.icure.kraken.client.models.decrypted.ContentDto> = mapOf()
)

@Mapper
interface ContactMapper {
    fun map(contact: ContactDto): io.icure.kraken.client.models.ContactDto
    fun map(contact: io.icure.kraken.client.models.ContactDto): ContactDto
}

object ContactMapperFactory {
    val instance = Mappers.getMapper(ContactMapper::class.java)
}

@Mapper
interface ServiceMapper {
    fun map(service: ServiceDto): io.icure.kraken.client.models.ServiceDto
    fun map(service: io.icure.kraken.client.models.ServiceDto): ServiceDto
}

object ServiceMapperFactory {
    val instance = Mappers.getMapper(ServiceMapper::class.java)
}
