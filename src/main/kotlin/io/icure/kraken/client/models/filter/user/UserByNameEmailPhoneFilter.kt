package io.icure.kraken.client.models.filter.user

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.filter.AbstractFilterDto

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class UserByNameEmailPhoneFilter (
    val searchString: String,
    override val desc: String? = null
) : AbstractFilterDto<UserDto>