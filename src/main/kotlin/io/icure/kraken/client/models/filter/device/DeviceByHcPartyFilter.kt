package io.icure.kraken.client.models.filter.device

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.DeviceDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class DeviceByHcPartyFilter(
        override val desc: String? = null,
        val responsibleId: String? = null
) : AbstractFilterDto<DeviceDto>

