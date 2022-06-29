package io.icure.kraken.client.extendedapis.infrastructure

import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.models.AuthenticationTokenDto
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.UserDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import java.time.Instant
import java.util.*
import kotlin.time.Duration.Companion.days

@OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class)
suspend fun UserApi.createUserForHcp(
    newHcp: HealthcarePartyDto,
    parent: HealthcarePartyDto
) = this.createUser(
    UserDto(
        id = UUID.randomUUID().toString(),
        login = "jimmy-${System.currentTimeMillis()}",
        type = UserDto.Type.database,
        status = UserDto.Status.aCTIVE,
        name = "${newHcp.firstName} ${newHcp.lastName}",
        authenticationTokens = mapOf(
            "test" to AuthenticationTokenDto(
                "test",
                Instant.now().toEpochMilli(),
                365.days.inWholeSeconds
            )
        ),
        healthcarePartyId = newHcp.id,
        autoDelegations = mapOf("all" to setOf(parent.id))
    )
)
