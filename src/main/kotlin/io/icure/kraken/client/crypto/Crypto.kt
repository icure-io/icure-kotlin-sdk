package io.icure.kraken.client.crypto

import io.icure.kraken.client.models.DelegationDto

interface Crypto {
    suspend fun decryptEncryptionKeys(myId: String, keys: Map<String, Set<DelegationDto>>): Set<String>
    suspend fun encryptKeyForHcp(myId: String, delegateId: String, objectId: String, secret: String): String
}
