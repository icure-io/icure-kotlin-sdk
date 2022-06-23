package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ContentDto
import io.icure.kraken.client.models.decrypted.ServiceDto
import org.mapstruct.Mapper

@Mapper
interface ServiceMapper {
    fun map(service: ServiceDto): io.icure.kraken.client.models.ServiceDto
    fun map(service: io.icure.kraken.client.models.ServiceDto): ServiceDto

    fun map(content: ContentDto): io.icure.kraken.client.models.ContentDto
    fun map(content: io.icure.kraken.client.models.ContentDto): ContentDto
}

object ServiceMapperFactory {
    val instance = ServiceMapperImpl()
}
