package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.AccessLogDto
import org.mapstruct.Mapper

@Mapper
interface AccessLogMapper {
    fun map(accessLog: AccessLogDto): io.icure.kraken.client.models.AccessLogDto
    fun map(accessLog: io.icure.kraken.client.models.AccessLogDto): AccessLogDto
}
object AccessLogMapperFactory {
    val instance = AccessLogMapperImpl()
}
