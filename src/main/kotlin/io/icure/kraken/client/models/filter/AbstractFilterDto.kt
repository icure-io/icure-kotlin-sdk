/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */
package io.icure.kraken.client.models.filter

import com.fasterxml.jackson.annotation.JsonProperty

interface AbstractFilterDto<O> {
    val desc: String?

    @JsonProperty(value = "\$type")
    fun getType(): String = this::class.java.simpleName
}





















