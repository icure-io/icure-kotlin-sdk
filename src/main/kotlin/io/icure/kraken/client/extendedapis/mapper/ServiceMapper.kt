package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ServiceDto
import org.mapstruct.InjectionStrategy
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper(uses = [ContentMapper::class], injectionStrategy = InjectionStrategy.CONSTRUCTOR)
interface ServiceMapper {
    fun map(service: ServiceDto): io.icure.kraken.client.models.ServiceDto
    fun map(service: io.icure.kraken.client.models.ServiceDto): ServiceDto
}

object ServiceMapperFactory {
    val instance = Mappers.getMapper(ServiceMapper::class.java)
}
