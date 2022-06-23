package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ClassificationDto
import org.mapstruct.Mapper

@Mapper
interface ClassificationMapper {
    fun map(classification: ClassificationDto): io.icure.kraken.client.models.ClassificationDto
    fun map(classification: io.icure.kraken.client.models.ClassificationDto): ClassificationDto
}

object ClassificationMapperFactory {
    val instance = ClassificationMapperImpl()
}
