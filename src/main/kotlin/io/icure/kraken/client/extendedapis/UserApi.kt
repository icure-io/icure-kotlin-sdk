package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.models.UserDto

fun UserDto.dataOwnerId() =
    this.healthcarePartyId ?: this.patientId ?: this.deviceId
    ?: throw IllegalAccessException("User is not a data owner")