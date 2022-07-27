package io.icure.kraken.client.extendedapis.infrastructure

import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.extendedapis.addNewKeyPair
import io.icure.kraken.client.extendedapis.initHcParty
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.UserDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import java.security.KeyPair
import java.util.*

@OptIn(
    ExperimentalStdlibApi::class, ExperimentalUnsignedTypes::class, FlowPreview::class,
    ExperimentalCoroutinesApi::class
)
suspend fun HealthcarePartyApi.createHealthcareParty(
    parentUser: UserDto,
    parentLocalCrypto: LocalCrypto,
    hcpKeyPair: KeyPair,
    firstName: String = "Jimmy",
    lastName: String = "Materazzi"
) = this.createHealthcareParty(
    HealthcarePartyDto(
        id = UUID.randomUUID().toString(),
        firstName = firstName,
        lastName = lastName
    )
        .initHcParty()
        .addNewKeyPair(parentUser, parentLocalCrypto, hcpKeyPair.public)
)
