/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */
package io.icure.kraken.client.models.filter.patient

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.PatientDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class PatientByHcPartyGenderEducationProfession(
        override val desc: String? = null,
        val healthcarePartyId: String? = null,
        val gender: PatientDto.Gender? = null,
        val education: String? = null,
        val profession: String? = null
) : AbstractFilterDto<PatientDto>
