/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */
package io.icure.kraken.client.models.filter.maintenancetask

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.IdentifierDto
import io.icure.kraken.client.models.MaintenanceTaskDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class MaintenanceTaskByHcPartyAndIdentifiersFilter(
	override val desc: String? = null,
	val healthcarePartyId: String? = null,
	val identifiers: List<IdentifierDto> = emptyList()
) : AbstractFilterDto<MaintenanceTaskDto>
