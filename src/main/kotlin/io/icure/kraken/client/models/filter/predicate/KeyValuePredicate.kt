/*
 * Copyright (c) 2020. Taktik SA, All rights reserved.
 */
package io.icure.kraken.client.models.filter.predicate

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonInclude

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
data class KeyValuePredicate(val key: String? = null, val operator: Operator? = null, val value: Any? = null) : Predicate {
    enum class Operator(val code: String) {
        EQUAL("=="),
        NOTEQUAL("!="),
        GREATERTHAN(">"),
        SMALLERTHAN("<"),
        GREATERTHANOREQUAL(">="),
        SMALLERTHANOREQUAL("<="),
        LIKE("%="),
        ILIKE("%%=");
        override fun toString(): String {
            return code
        }
    }
}
