/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */

package io.icure.kraken.client.models.filter

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class ComplementFilter<O>(
        override val desc: String? = null,
        val superSet: AbstractFilterDto<O>,
        val subSet: AbstractFilterDto<O>
) : AbstractFilterDto<O>
