package io.icure.kraken.client.models.filter.code

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.CodeDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class CodeIdsByTypeCodeVersionIntervalFilter (
    val startType: String? = null,
    val startCode: String? = null,
    val startVersion: String? = null,
    val endType: String? = null,
    val endCode: String? = null,
    val endVersion: String? = null,
    override val desc: String? = null
) : AbstractFilterDto<CodeDto>