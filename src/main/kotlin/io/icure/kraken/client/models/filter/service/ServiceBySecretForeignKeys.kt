/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */
package io.icure.kraken.client.models.filter.service

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import com.github.pozo.KotlinBuilder
import io.icure.kraken.client.models.ServiceDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@KotlinBuilder
data class ServiceBySecretForeignKeys(
        override val desc:String? = null,
        val healthcarePartyId: String? = null,
        val patientSecretForeignKeys: Set<String>
) : AbstractFilterDto<ServiceDto>
