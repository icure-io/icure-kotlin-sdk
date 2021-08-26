/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */

package io.icure.kraken.client.models.filter.code

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.CodeDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class CodeByRegionTypeLabelLanguageFilter(
        override val desc:String? = null,
        val region: String? = null,
        val type: String? = null,
        val language: String? = null,
        val label: String? = null
) : AbstractFilterDto<CodeDto>
