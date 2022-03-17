package io.icure.kraken.client.crypto

import io.icure.kraken.client.extendedapis.DataOwner
import io.icure.kraken.client.models.DelegationDto

interface Crypto {
    suspend fun decryptEncryptionKeys(myId: String, keys: Map<String, Set<DelegationDto>>): Set<String>
    suspend fun encryptAESKeyForDataOwner(myId: String, delegateId: String, objectId: String, secret: String): Pair<String, DataOwner?>
    suspend fun encryptValueForDataOwner(myId: String, delegateId: String, objectId: String, secret: String): Pair<String, DataOwner?>
}
