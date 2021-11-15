package io.icure.kraken.client.models.filter.service

import io.icure.kraken.client.models.ServiceDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

data class ServiceByHcPartyIdentifierFilter(
    val healthcarePartyId: String? = null,
    val system: String? = null,
    val value: String? = null,
    override val desc: String? = null
) : AbstractFilterDto<ServiceDto>
