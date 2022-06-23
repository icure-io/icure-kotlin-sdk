package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ContactDto
import org.mapstruct.InjectionStrategy
import org.mapstruct.Mapper

@Mapper(uses = [ServiceMapper::class], injectionStrategy = InjectionStrategy.CONSTRUCTOR)
interface ContactMapper {
    fun map(contact: ContactDto): io.icure.kraken.client.models.ContactDto
    fun map(contact: io.icure.kraken.client.models.ContactDto): ContactDto
}

object ContactMapperFactory {
    val instance = ContactMapperImpl(ServiceMapperImpl())
}
