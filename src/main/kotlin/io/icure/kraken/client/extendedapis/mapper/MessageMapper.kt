package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.MessageDto
import org.mapstruct.Mapper

@Mapper
interface MessageMapper {
    fun map(message: MessageDto): io.icure.kraken.client.models.MessageDto
    fun map(message: io.icure.kraken.client.models.MessageDto): MessageDto
}

object MessageMapperFactory {
    val instance = MessageMapperImpl()
}
