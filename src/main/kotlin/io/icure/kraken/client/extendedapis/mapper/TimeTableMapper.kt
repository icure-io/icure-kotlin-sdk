package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.TimeTableDto
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers

@Mapper
interface TimeTableMapper {
    fun map(timeTable: TimeTableDto): io.icure.kraken.client.models.TimeTableDto
    fun map(timeTable: io.icure.kraken.client.models.TimeTableDto): TimeTableDto
}

object TimeTableMapperFactory {
    val instance = Mappers.getMapper(TimeTableMapper::class.java)
}
