package io.icure.kraken.client.crypto

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.defGet
import io.icure.kraken.client.defPut
import io.icure.kraken.client.exception.MissingPrivateKeyException
import io.icure.kraken.client.extendedapis.DataOwner
import io.icure.kraken.client.extendedapis.DataOwnerResolver
import io.icure.kraken.client.models.DelegationDto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.async
import java.security.*
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.concurrent.TimeUnit

@FlowPreview
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
class LocalCrypto(
    private val dataOwnerResolver: DataOwnerResolver,
    private val rsaKeyPairs: Map<String, Pair<RSAPrivateKey, RSAPublicKey>>
) : Crypto {
    private val aesValidKeySizes : Set<Int> = setOf(128, 192, 256)

    private val ownerHcpartyKeysCache : Cache<String, Deferred<Optional<Map<String, Pair<String, ByteArray>>>>> = Caffeine.newBuilder()
        .maximumSize(100)
        .expireAfterWrite(5, TimeUnit.MINUTES)
        .build()
    private val delegateHcpartyKeysCache : Cache<String, Deferred<Optional<Map<String, Pair<String, ByteArray>>>>> = Caffeine.newBuilder()
        .maximumSize(100)
        .expireAfterWrite(5, TimeUnit.MINUTES)
        .build()

    override suspend fun decryptEncryptionKeys(myId: String, keys: Map<String, Set<DelegationDto>>): Set<String> {
        return ((keys[myId]?.mapNotNull { d ->
            try {
                getDelegateHcPartyKey(d.delegatedTo!!, d.owner!!)
            } catch (e: Exception) {
                null
            }?.let { k -> decryptAES(d.key!!.keyFromHexString(), k).toString(Charsets.UTF_8)
                .split(":")[1]
            }
        }?.toSet() ?: emptySet()) + (dataOwnerResolver.getDataOwner(myId).parentId?.let { decryptEncryptionKeys(it, keys) } ?: emptySet())).takeIf { it.isNotEmpty() } ?: throw IllegalArgumentException("Missing key for $myId")
    }

    override suspend fun encryptAESKeyForDataOwner(myId: String, delegateId: String, objectId: String, secret: String): Pair<String, DataOwner?> {
        val secretKey = formatKey(secret)
        if (secretKey.keyFromHexString().size * 8 !in aesValidKeySizes) {
            throw IllegalArgumentException("Illegal AES key size : Secret length should be either 128, 192 or 256")
        }
        val (key, dataOwner) = getOrCreateHcPartyKey(myId, delegateId)
        return encryptAES("$objectId:$secretKey".toByteArray(Charsets.UTF_8), key).keyToHexString() to dataOwner
    }

    override suspend fun encryptValueForDataOwner(myId: String, delegateId: String, objectId: String, secret: String): Pair<String, DataOwner?> {
        val (key, dataOwner) = getOrCreateHcPartyKey(myId, delegateId)
        return encryptAES("$objectId:$secret".toByteArray(Charsets.UTF_8), key).keyToHexString() to dataOwner
    }

    private fun formatKey(key: String) : String {
        return try {
            UUID.fromString(key).let { key.replace("-", "") }
        } catch (e : IllegalArgumentException) {
            key
        }
    }

    suspend fun getDelegateHcPartyKey(delegateId: String, ownerId: String, myPrivateKey: PrivateKey? = null): ByteArray {
        val privateKey = myPrivateKey ?: rsaKeyPairs[delegateId]?.first ?: throw MissingPrivateKeyException(delegateId, "Missing key for hcp $delegateId")
        val keyMap: Map<String, Pair<String, ByteArray>> =
            delegateHcpartyKeysCache.defGet(delegateId) {
                dataOwnerResolver.getDataOwnerHcPartyKeysForDelegate(delegateId).decryptHcPartyKeys(delegateId, privateKey)
            } ?: throw IllegalArgumentException("Unknown hcp $delegateId")

        return keyMap[ownerId]?.second ?: throw IllegalArgumentException("Missing share for $ownerId")
    }

    private suspend fun getDataOwnerPublicKey(dataOwnerId: String) : String? {
        return dataOwnerResolver.getDataOwner(dataOwnerId).publicKey
    }

    private suspend fun getDataOwnerHcPartyKeys(dataOwnerId: String) : Map<String, List<String>> {
        return dataOwnerResolver.getDataOwner(dataOwnerId).hcPartyKeys
    }

    suspend fun getOrCreateHcPartyKey(myId: String, delegateId: String, privateKey: PrivateKey? = null, publicKey: PublicKey? = null): Pair<ByteArray, DataOwner?> {
        val myPublicKey = publicKey ?: rsaKeyPairs[myId]?.second ?: throw IllegalArgumentException("Missing key for hcp $myId")
        val myPrivateKey = privateKey ?: rsaKeyPairs[myId]?.first ?: throw MissingPrivateKeyException(myId, "Missing key for hcp $myId")
        val keyMap: Map<String, Pair<String, ByteArray>> =
            ownerHcpartyKeysCache.defGet(myId) {
                getDataOwnerHcPartyKeys(myId).mapValues { (_, v) -> v[0] }.decryptHcPartyKeys(myId, myPrivateKey)
            } ?: throw IllegalArgumentException("Unknown hcp $myId")

        return keyMap[delegateId]?.second?.let { it to null } ?: CryptoUtils.generateKeyAES().encoded.let {
            val keyForMe = CryptoUtils.encryptRSA(it, myPublicKey).keyToHexString()
            val keyForDelegate = CryptoUtils.encryptRSA(
                it,
                getDataOwnerPublicKey(delegateId)?.let { pk ->
                    KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(pk.keyFromHexString()))
                } ?: throw IllegalArgumentException("Unknown hcp $delegateId")
            ).keyToHexString()
            it to dataOwnerResolver.getDataOwner(myId).let { hcp ->
                CoroutineScope(Dispatchers.IO).async { dataOwnerResolver.updateDataOwnerWithNewHcPartyKeys(
                    hcp.type, hcp.dataOwnerId, (delegateId to listOf(
                        keyForMe,
                        keyForDelegate
                    ))
                ) }.also { deferredNewDataOwner ->
                    ownerHcpartyKeysCache.defPut(myId) {
                        deferredNewDataOwner.await().hcPartyKeys.mapValues { (_, v) -> v[0] }.decryptHcPartyKeys(myId, myPrivateKey)
                    }
                }
            }.await()
        }
    }

    /** Decrypt hcparty keys
     *
     */
    private fun Map<String, String>.decryptHcPartyKeys(
        myId: String,
        myPrivateKey: PrivateKey
    ) = this.mapValues { (_, v) ->
        v to CryptoUtils.decryptRSA(
            v.keyFromHexString() ?: throw IllegalArgumentException("Invalid HCP key for hcp $myId"),
            myPrivateKey
        )
    }
}
