/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */
package io.icure.kraken.client.models.filter.service

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.ServiceDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class ServiceByContactsAndSubcontactsFilter(
        override val desc:String? = null,
        val healthcarePartyId: String? = null,
        val contacts: Set<String>,
        val subContacts: Set<String>? = null,
        val startValueDate: Long? = null,
        val endValueDate: Long? = null
) : AbstractFilterDto<ServiceDto>
