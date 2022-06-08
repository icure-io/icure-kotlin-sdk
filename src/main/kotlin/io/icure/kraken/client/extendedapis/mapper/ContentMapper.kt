package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ContentDto
import org.mapstruct.InjectionStrategy
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper(uses = [ServiceMapper::class], injectionStrategy = InjectionStrategy.CONSTRUCTOR)
interface ContentMapper {
    fun map(content: ContentDto): io.icure.kraken.client.models.ContentDto
    fun map(content: io.icure.kraken.client.models.ContentDto): ContentDto
}

object ContentMapperFactory {
    val instance = Mappers.getMapper(ContentMapper::class.java)
}
