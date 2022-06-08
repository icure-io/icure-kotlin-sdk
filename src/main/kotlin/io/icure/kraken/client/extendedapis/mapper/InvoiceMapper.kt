package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.InvoiceDto
import org.mapstruct.InjectionStrategy
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper(injectionStrategy = InjectionStrategy.CONSTRUCTOR)
interface InvoiceMapper {
    fun map(invoice: InvoiceDto): io.icure.kraken.client.models.InvoiceDto
    fun map(invoice: io.icure.kraken.client.models.InvoiceDto): InvoiceDto
}

object InvoiceMapperFactory {
    val instance = Mappers.getMapper(InvoiceMapper::class.java)
}
