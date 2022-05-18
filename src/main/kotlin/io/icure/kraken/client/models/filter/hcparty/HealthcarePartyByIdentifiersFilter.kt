package io.icure.kraken.client.models.filter.hcparty

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.IdentifierDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class HealthcarePartyByIdentifiersFilter(
    val identifiers: List<IdentifierDto> = emptyList(),
    override val desc: String? = null
) : AbstractFilterDto<HealthcarePartyDto>
