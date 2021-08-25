/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */
package io.icure.kraken.client.models.filter.patient


import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder
import io.icure.kraken.client.models.PatientDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class PatientByHcPartyAndSsinsFilter(
        override val desc: String? = null,
        val ssins: List<String>? = null,
        val healthcarePartyId: String? = null
) : AbstractFilterDto<PatientDto>
