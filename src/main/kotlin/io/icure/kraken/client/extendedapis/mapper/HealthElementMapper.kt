package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.HealthElementDto
import org.mapstruct.Mapper

@Mapper
interface HealthElementMapper {
    fun map(healthElement: HealthElementDto): io.icure.kraken.client.models.HealthElementDto
    fun map(healthElement: io.icure.kraken.client.models.HealthElementDto): HealthElementDto
}

object HealthElementMapperFactory {
    val instance = HealthElementMapperImpl()
}
