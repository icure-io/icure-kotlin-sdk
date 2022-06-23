package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.ReceiptDto
import org.mapstruct.Mapper

@Mapper
interface ReceiptMapper {
    fun map(receipt: ReceiptDto): io.icure.kraken.client.models.ReceiptDto
    fun map(receipt: io.icure.kraken.client.models.ReceiptDto): ReceiptDto
}

object ReceiptMapperFactory {
    val instance = ReceiptMapperImpl()
}
