package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.DocumentDto
import org.mapstruct.Mapper

@Mapper
interface DocumentMapper {
    fun map(document: DocumentDto): io.icure.kraken.client.models.DocumentDto
    fun map(document: io.icure.kraken.client.models.DocumentDto): DocumentDto
}

object DocumentMapperFactory {
    val instance = DocumentMapperImpl()
}
