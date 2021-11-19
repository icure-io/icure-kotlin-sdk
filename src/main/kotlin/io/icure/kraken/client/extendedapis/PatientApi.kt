package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.*
import io.icure.kraken.client.models.decrypted.PaginatedListPatientDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun PatientDto.initDelegations(user: UserDto, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>): PatientDto {
    val delegations =  (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf())
    val ek = UUID.randomUUID().toString()
    val sfk = UUID.randomUUID().toString()
    return this.copy(
        responsible = this.responsible ?: user.healthcarePartyId!!,
        author = user.id,
        delegations = (delegations + user.healthcarePartyId!!).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    listOf(), user.healthcarePartyId, d, config.crypto.encryptAESKeyForHcp(user.healthcarePartyId, d, this.id, sfk),
                ),
            ))
        },
        encryptionKeys = (delegations + user.healthcarePartyId).fold(this.encryptionKeys) { m, d ->
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
suspend fun PatientApi.createPatient(user: UserDto, patient: PatientDto, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) =
    this.createPatient(
        config.encryptPatient(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            patient.initDelegations(user, config)
        )
    )?.let { config.decryptPatient(user.healthcarePartyId, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.modifyPatient(user: UserDto, patient: PatientDto, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) =
    this.modifyPatient(
        config.encryptPatient(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            patient
        )
    )?.let { config.decryptPatient(user.healthcarePartyId, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.bulkCreatePatients(user: UserDto, patientDto: List<PatientDto>, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<IdWithRevDto>? {
    return this.bulkCreatePatients(patientDto.map { config.encryptPatient(
        user.healthcarePartyId!!,
        (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
        it.initDelegations(user, config)
    ) })
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.bulkUpdatePatients(user: UserDto, patientDto: List<PatientDto>, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<IdWithRevDto>? {
    return this.bulkUpdatePatients(patientDto.map { config.encryptPatient(
        user.healthcarePartyId!!,
        (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
        it
    ) })
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.filterPatientsBy(user: UserDto, filterChainPatient: FilterChainPatient, startKey: String?, startDocumentId: String?, limit: Int?, skip: Int?, sort: String?, desc: Boolean?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto? {
    return this.filterPatientsBy(filterChainPatient, startKey, startDocumentId, limit, skip, sort, desc)?.let {
        PaginatedListPatientDto(rows = it.rows?.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.findByAccessLogUserAfterDate(user: UserDto, userId: String, accessType: String?, startDate: Long?, startKey: String?, startDocumentId: String?, limit: Int?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto? {
    return this.findByAccessLogUserAfterDate(userId, accessType, startDate, startKey, startDocumentId, limit)?.let {
        PaginatedListPatientDto(rows = it.rows?.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.findByExternalId(user: UserDto, externalId: String, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto? {
    return this.findByExternalId(externalId)?.let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.findByNameBirthSsinAuto(user: UserDto, healthcarePartyId: String?, filterValue: String?, startKey: String?, startDocumentId: String?, limit: Int?, sortDirection: String?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto? {
    return this.findByNameBirthSsinAuto(healthcarePartyId, filterValue, startKey, startDocumentId, limit, sortDirection)?.let {
        PaginatedListPatientDto(rows = it.rows?.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.fuzzySearch(user: UserDto, firstName: String?, lastName: String?, dateOfBirth: Int?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<PatientDto>? {
    return this.fuzzySearch(firstName, lastName, dateOfBirth)?.map { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.getPatientByHealthcarepartyAndIdentifier(user: UserDto, hcPartyId: kotlin.String, system: kotlin.String, id: kotlin.String, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto? {
    return this.getPatientByHealthcarepartyAndIdentifier(hcPartyId = hcPartyId, system = system, id = id)?.let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.getPatient(user: UserDto, patientId: String, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto? {
    return this.getPatient(patientId)?.let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.getPatients(user: UserDto, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<PatientDto>? {
    return this.getPatients(listOfIdsDto)?.map { config.decryptPatient(user.healthcarePartyId!!, it) }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listDeletedPatients(user: UserDto, startDate: Long?, endDate: Long?, desc: Boolean?, startDocumentId: String?, limit: Int?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto? {
    return this.listDeletedPatients(startDate, endDate, desc, startDocumentId, limit)?.let {
        PaginatedListPatientDto(rows = it.rows?.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listDeletedPatientsByName(user: UserDto, firstName: String?, lastName: String?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<PatientDto>? {
    return this.listDeletedPatientsByName(firstName, lastName)?.map { config.decryptPatient(user.healthcarePartyId!!, it) }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listOfMergesAfter(user: UserDto, date: Long, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<PatientDto>? {
    return this.listOfMergesAfter(date)?.map { config.decryptPatient(user.healthcarePartyId!!, it) }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listOfPatientsModifiedAfter(user: UserDto, date: Long, startKey: Long?, startDocumentId: String?, limit: Int?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto? {
    return this.listOfPatientsModifiedAfter(date, startKey, startDocumentId, limit)?.let {
        PaginatedListPatientDto(rows = it.rows?.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listPatients(user: UserDto, hcPartyId: String?, sortField: String?, startKey: String?, startDocumentId: String?, limit: Int?, sortDirection: String?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto? {
    return this.listPatients(hcPartyId, sortField, startKey, startDocumentId, limit, sortDirection)?.let {
        PaginatedListPatientDto(rows = it.rows?.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listPatientsByHcParty(user: UserDto, hcPartyId: String, sortField: String?, startKey: String?, startDocumentId: String?, limit: Int?, sortDirection: String?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto? {
    return this.listPatientsByHcParty(hcPartyId, sortField, startKey, startDocumentId, limit, sortDirection)?.let {
        PaginatedListPatientDto(rows = it.rows?.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listPatientsOfHcParty(user: UserDto, hcPartyId: String, sortField: String?, startKey: String?, startDocumentId: String?, limit: Int?, sortDirection: String?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto? {
    return this.listPatientsOfHcParty(hcPartyId, sortField, startKey, startDocumentId, limit, sortDirection)?.let {
        PaginatedListPatientDto(rows = it.rows?.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.mergeInto(user: UserDto, toId: String, fromIds: String, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto? {
    return this.mergeInto(toId, fromIds)?.let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.modifyPatientReferral(user: UserDto, patientId: String, referralId: String, start: Long?, end: Long?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto? {
    return this.modifyPatientReferral(patientId, referralId, start, end)?.let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.newPatientDelegations(user: UserDto, patientId: String, delegationDto: List<DelegationDto>, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto? {
    return this.newPatientDelegations(patientId, delegationDto)?.let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

suspend fun CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>.encryptPatient(myId: String, delegations: Set<String>, patient: PatientDto): io.icure.kraken.client.models.PatientDto {
    return if (patient.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        patient
    } else {
        val secret = UUID.randomUUID().toString()
        patient.copy(encryptionKeys = (delegations + myId).fold(patient.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(listOf(), myId, d, this.crypto.encryptAESKeyForHcp(myId, d, patient.id, secret))))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys).firstOrNull()?.keyFromHexString()
            ?: throw IllegalArgumentException("No encryption key for user")
        val (sanitizedPatient, marshalledData) = this.marshaller(p)
        sanitizedPatient.copy(encryptedSelf = Base64.getEncoder().encodeToString(encryptAES(data = marshalledData, key = key)))
    }
}

suspend fun CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>.decryptPatient(myId: String, patient: io.icure.kraken.client.models.PatientDto): PatientDto {
    return try {
        val key = this.crypto.decryptEncryptionKeys(myId, patient.encryptionKeys).firstOrNull()?.keyFromHexString()
            ?: throw IllegalArgumentException("No encryption key for user")
        this.unmarshaller(patient, decryptAES(data = Base64.getDecoder().decode(patient.encryptedSelf), key = key))
    }
    catch (ex : IllegalArgumentException){
        PatientMapperFactory.instance.map(patient)
    }
}

@Mapper
interface PatientMapper {
    fun map(patient: PatientDto): io.icure.kraken.client.models.PatientDto
    fun map(patient: io.icure.kraken.client.models.PatientDto): PatientDto
}

object PatientMapperFactory {
    val instance = Mappers.getMapper(PatientMapper::class.java)
}
