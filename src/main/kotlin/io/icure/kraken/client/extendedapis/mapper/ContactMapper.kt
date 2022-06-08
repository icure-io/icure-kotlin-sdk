package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ContactDto
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper(uses = [ServiceMapper::class])
interface ContactMapper {
    fun map(contact: ContactDto): io.icure.kraken.client.models.ContactDto
    fun map(contact: io.icure.kraken.client.models.ContactDto): ContactDto
}

object ContactMapperFactory {
    val instance = Mappers.getMapper(ContactMapper::class.java)
}
