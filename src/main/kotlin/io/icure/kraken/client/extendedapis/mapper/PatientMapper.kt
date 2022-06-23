package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.PatientDto
import org.mapstruct.Mapper

@Mapper
interface PatientMapper {
    fun map(patient: PatientDto): io.icure.kraken.client.models.PatientDto
    fun map(patient: io.icure.kraken.client.models.PatientDto): PatientDto
}

object PatientMapperFactory {
    val instance = PatientMapperImpl()
}
