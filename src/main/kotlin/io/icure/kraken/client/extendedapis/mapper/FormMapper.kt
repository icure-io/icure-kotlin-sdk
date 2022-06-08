package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.FormDto
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper
interface FormMapper {
    fun map(form: FormDto): io.icure.kraken.client.models.FormDto
    fun map(form: io.icure.kraken.client.models.FormDto): FormDto
}

object FormMapperFactory {
    val instance = Mappers.getMapper(FormMapper::class.java)
}
