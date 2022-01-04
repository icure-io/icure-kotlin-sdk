package io.icure.kraken.client.models.filter.healthelement

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.HealthElementDto
import io.icure.kraken.client.models.IdentifierDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class HealthElementByHcPartyAndIdentifiersFilter(
    override val desc: String? = null,
    val healthcarePartyId: String? = null,
    val identifiers: List<IdentifierDto> = emptyList(),
): AbstractFilterDto<HealthElementDto>
