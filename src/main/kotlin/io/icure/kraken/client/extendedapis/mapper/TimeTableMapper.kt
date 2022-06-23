package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.TimeTableDto
import org.mapstruct.Mapper

@Mapper
interface TimeTableMapper {
    fun map(timeTable: TimeTableDto): io.icure.kraken.client.models.TimeTableDto
    fun map(timeTable: io.icure.kraken.client.models.TimeTableDto): TimeTableDto
}

object TimeTableMapperFactory {
    val instance = TimeTableMapperImpl()
}
