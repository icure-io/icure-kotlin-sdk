package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.HealthElementDto
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper
interface HealthElementMapper {
    fun map(healthElement: HealthElementDto): io.icure.kraken.client.models.HealthElementDto
    fun map(healthElement: io.icure.kraken.client.models.HealthElementDto): HealthElementDto
}

object HealthElementMapperFactory {
    val instance = Mappers.getMapper(HealthElementMapper::class.java)
}
