package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.crypto.Crypto
import io.icure.kraken.client.models.DeviceDto
import java.security.PrivateKey
import java.security.PublicKey

suspend fun DeviceDto.addNewKeyPair(crypto: Crypto,
                                    devicePublicKey: PublicKey,
                                    devicePrivateKey: PrivateKey? = null
) = crypto.addNewKeyPairTo(this.toDataOwner(), devicePublicKey, devicePrivateKey).let { dataOwner ->
    this.copy(
        publicKey = dataOwner.publicKey,
        hcPartyKeys = dataOwner.hcPartyKeys,
        aesExchangeKeys = dataOwner.aesExchangeKeys,
        transferKeys = dataOwner.transferKeys
    )
}