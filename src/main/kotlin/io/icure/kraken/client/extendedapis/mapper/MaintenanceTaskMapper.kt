package io.icure.kraken.client.extendedapis.mapper

import io.icure.kraken.client.models.decrypted.MaintenanceTaskDto
import org.mapstruct.Mapper

@Mapper
interface MaintenanceTaskMapper {
    fun map(maintenanceTask: MaintenanceTaskDto): io.icure.kraken.client.models.MaintenanceTaskDto
    fun map(maintenanceTask: io.icure.kraken.client.models.MaintenanceTaskDto): MaintenanceTaskDto
}

object MaintenanceTaskMapperFactory {
    val instance = MaintenanceTaskMapperImpl()
}
