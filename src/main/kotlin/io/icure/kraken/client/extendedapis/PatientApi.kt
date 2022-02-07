package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.applyIf
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.DelegationDto
import io.icure.kraken.client.models.IdWithRevDto
import io.icure.kraken.client.models.ListOfIdsDto
import io.icure.kraken.client.models.PersonNameDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.PaginatedListPatientDto
import io.icure.kraken.client.models.decrypted.PatientDto
import io.icure.kraken.client.models.filter.chain.FilterChain
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

fun PatientDto.initPatient() : PatientDto {
    return this
        .applyIf({ p -> p.lastName == null && p.hasName(PersonNameDto.Use.official)}) { p ->
            p.copy(lastName = p.findName(PersonNameDto.Use.official)!!.lastName)
        }
        .applyIf({ p -> p.firstName == null && p.hasName(PersonNameDto.Use.official)}) { p ->
            p.copy(firstName = p.findName(PersonNameDto.Use.official)!!.firstNames.firstOrNull())
        }
        .applyIf({ p -> p.maidenName == null && p.hasName(PersonNameDto.Use.maiden)}) { p ->
            p.copy(maidenName = p.findName(PersonNameDto.Use.maiden)!!.lastName)
        }
        .applyIf({ p -> p.alias == null && p.hasName(PersonNameDto.Use.nickname)}) { p ->
            p.copy(alias = p.findName(PersonNameDto.Use.nickname)!!.lastName)
        }
        .applyIf({ p -> p.lastName != null && !p.hasName(PersonNameDto.Use.official)}) { p ->
            p.addName(PersonNameDto.Use.official, p.lastName!!, p.firstName)
        }
        .applyIf({ p -> p.maidenName != null && !p.hasName(PersonNameDto.Use.maiden)}) { p ->
            p.addName(PersonNameDto.Use.maiden, p.maidenName!!, p.firstName)
        }
        .applyIf({ p -> p.alias != null && !p.hasName(PersonNameDto.Use.nickname)}) { p ->
            p.addName(PersonNameDto.Use.nickname, p.alias!!, p.firstName)
        }
}

fun PatientDto.hasName(nameUse: PersonNameDto.Use) : Boolean {
    return this.names.any { it.use == nameUse }
}

fun PatientDto.findName(nameUse: PersonNameDto.Use) : PersonNameDto? {
    return this.names.find { it.use == nameUse }
}

private fun PatientDto.addName(use: PersonNameDto.Use, lastName: String, firstName: String?) =
    this.copy(names = this.names + listOf(PersonNameDto(lastName = lastName, firstNames = listOfNotNull(firstName), use = use)))


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
suspend fun PatientApi.createPatient(user: UserDto, patient: PatientDto, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) =
    this.createPatient(
        config.encryptPatient(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            patient.initPatient().initDelegations(user, config)
        )
    ).let { config.decryptPatient(user.healthcarePartyId, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.modifyPatient(user: UserDto, patient: PatientDto, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) =
    this.modifyPatient(
        config.encryptPatient(
            user.healthcarePartyId!!,
            (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
            patient.initPatient()
        )
    ).let { config.decryptPatient(user.healthcarePartyId, it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.bulkDeletePatients(user: UserDto, patients: List<PatientDto>, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<IdWithRevDto> {
    val currentTime = System.currentTimeMillis()
    val updatedPatients = patients.map { it.copy(endOfLife = currentTime) }

    return bulkUpdatePatients(user, updatedPatients, config)
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.bulkCreatePatients(user: UserDto, patientDto: List<PatientDto>, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<IdWithRevDto> {
    return this.createPatients(patientDto.map { config.encryptPatient(
        user.healthcarePartyId!!,
        (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
        it.initPatient().initDelegations(user, config)
    ) })
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.bulkUpdatePatients(user: UserDto, patientDto: List<PatientDto>, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<IdWithRevDto> {
    return this.modifyPatients(patientDto.map { config.encryptPatient(
        user.healthcarePartyId!!,
        (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"] ?: setOf()),
        it.initPatient()
    ) })
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.filterPatientsBy(user: UserDto, filterChainPatient: FilterChain<io.icure.kraken.client.models.PatientDto>, startKey: String?, startDocumentId: String?, limit: Int?, skip: Int?, sort: String?, desc: Boolean?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto {
    return this.filterPatientsBy(filterChainPatient, startKey, startDocumentId, limit, skip, sort, desc).let {
        PaginatedListPatientDto(rows = it.rows.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.findByAccessLogUserAfterDate(user: UserDto, userId: String, accessType: String?, startDate: Long?, startKey: String?, startDocumentId: String?, limit: Int?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto {
    return this.findPatientsByAccessLogUserAfterDate(userId, accessType, startDate, startKey, startDocumentId, limit).let {
        PaginatedListPatientDto(rows = it.rows.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.findByExternalId(user: UserDto, externalId: String, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto {
    return this.getPatientByExternalId(externalId).let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.findByNameBirthSsinAuto(user: UserDto, healthcarePartyId: String?, filterValue: String?, startKey: String?, startDocumentId: String?, limit: Int?, sortDirection: String?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto {
    return this.findPatientsByNameBirthSsinAuto(healthcarePartyId, filterValue, startKey, startDocumentId, limit, sortDirection).let {
        PaginatedListPatientDto(rows = it.rows.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.fuzzySearch(user: UserDto, firstName: String?, lastName: String?, dateOfBirth: Int?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<PatientDto> {
    return this.fuzzySearch(firstName, lastName, dateOfBirth).map { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.getPatient(user: UserDto, patientId: String, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto {
    return this.getPatient(patientId).let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.getPatients(user: UserDto, listOfIdsDto: ListOfIdsDto, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<PatientDto> {
    return this.getPatients(listOfIdsDto).map { config.decryptPatient(user.healthcarePartyId!!, it) }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listDeletedPatients(user: UserDto, startDate: Long?, endDate: Long?, desc: Boolean?, startDocumentId: String?, limit: Int?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto {
    return this.findDeletedPatients(startDate, endDate, desc, startDocumentId, limit).let {
        PaginatedListPatientDto(rows = it.rows.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listDeletedPatientsByName(user: UserDto, firstName: String?, lastName: String?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<PatientDto> {
    return this.listDeletedPatientsByName(firstName, lastName).map { config.decryptPatient(user.healthcarePartyId!!, it) }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listOfMergesAfter(user: UserDto, date: Long, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : List<PatientDto> {
    return this.listOfMergesAfter(date).map { config.decryptPatient(user.healthcarePartyId!!, it) }
}
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listOfPatientsModifiedAfter(user: UserDto, date: Long, startKey: Long?, startDocumentId: String?, limit: Int?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto {
    return this.findPatientsModifiedAfter(date, startKey, startDocumentId, limit).let {
        PaginatedListPatientDto(rows = it.rows.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listPatients(user: UserDto, hcPartyId: String?, sortField: String?, startKey: String?, startDocumentId: String?, limit: Int?, sortDirection: String?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto {
    return this.findPatientsByHealthcareParty(hcPartyId, sortField, startKey, startDocumentId, limit, sortDirection).let {
        PaginatedListPatientDto(rows = it.rows.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.listPatientsByHcParty(user: UserDto, hcPartyId: String, sortField: String?, startKey: String?, startDocumentId: String?, limit: Int?, sortDirection: String?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PaginatedListPatientDto {
    return this.findPatientsByHealthcareParty(hcPartyId, sortField, startKey, startDocumentId, limit, sortDirection).let {
        PaginatedListPatientDto(rows = it.rows.map { config.decryptPatient(user.healthcarePartyId!!, it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
    }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.mergeInto(user: UserDto, toId: String, fromIds: String, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto {
    return this.mergeInto(toId, fromIds).let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.modifyPatientReferral(user: UserDto, patientId: String, referralId: String, start: Long?, end: Long?, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto {
    return this.modifyPatientReferral(patientId, referralId, start, end).let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun PatientApi.newPatientDelegations(user: UserDto, patientId: String, delegationDto: List<DelegationDto>, config: CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>) : PatientDto {
    return this.newPatientDelegations(patientId, delegationDto).let { config.decryptPatient(user.healthcarePartyId!!, it) }
}

suspend fun CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>.encryptPatient(myId: String, delegations: Set<String>, patient: PatientDto): io.icure.kraken.client.models.PatientDto {
    return if (patient.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        patient
    } else {
        val secret = UUID.randomUUID().toString()
        patient.copy(encryptionKeys = (delegations + myId).fold(patient.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(emptyList(), myId, d, this.crypto.encryptAESKeyForHcp(myId, d, patient.id, secret))))
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
