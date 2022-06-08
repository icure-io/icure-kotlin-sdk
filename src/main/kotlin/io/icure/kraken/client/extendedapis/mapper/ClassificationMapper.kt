package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ClassificationDto
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper
interface ClassificationMapper {
    fun map(classification: ClassificationDto): io.icure.kraken.client.models.ClassificationDto
    fun map(classification: io.icure.kraken.client.models.ClassificationDto): ClassificationDto
}

object ClassificationMapperFactory {
    val instance = Mappers.getMapper(ClassificationMapper::class.java)
}
