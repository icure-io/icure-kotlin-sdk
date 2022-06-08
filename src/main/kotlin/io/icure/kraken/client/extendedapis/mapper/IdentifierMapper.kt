package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.Identifier
import io.icure.kraken.client.models.IdentifierDto
import org.mapstruct.InjectionStrategy
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper(uses = [CodeStubMapper::class], injectionStrategy = InjectionStrategy.CONSTRUCTOR)
interface IdentifierMapper {
    fun map(identifier: IdentifierDto): Identifier
    fun map(identifier: Identifier): IdentifierDto
}

object IdentifierMapperFactory {
    val instance = Mappers.getMapper(IdentifierMapper::class.java)
}
