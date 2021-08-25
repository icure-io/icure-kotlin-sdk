/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */

package io.icure.kraken.client.models.filter

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class ConstantFilter<O>(
        override val desc: String? = null,
        val constant: Set<String>
) : AbstractFilterDto<O>
