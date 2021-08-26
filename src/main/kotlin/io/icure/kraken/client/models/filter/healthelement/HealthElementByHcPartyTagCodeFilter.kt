/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */

package io.icure.kraken.client.models.filter.healthelement

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.HealthElementDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class HealthElementByHcPartyTagCodeFilter(
        override val desc:String? = null,
        val healthCarePartyId: String? = null,
        val codeType: String? = null,
        val codeNumber: String? = null,
        val tagType: String? = null,
        val tagCode: String? = null,
        val status: Int? = null
        ) : AbstractFilterDto<HealthElementDto>
