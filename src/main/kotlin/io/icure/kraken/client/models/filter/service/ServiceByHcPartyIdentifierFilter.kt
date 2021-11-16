package io.icure.kraken.client.models.filter.service

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.ServiceDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class ServiceByHcPartyIdentifierFilter(
    val healthcarePartyId: String? = null,
    val system: String? = null,
    val value: String? = null,
    override val desc: String? = null
) : AbstractFilterDto<ServiceDto>
