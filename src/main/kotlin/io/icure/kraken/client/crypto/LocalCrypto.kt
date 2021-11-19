package io.icure.kraken.client.crypto

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import io.icure.kraken.client.apis.HcpartyApi
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.defGet
import io.icure.kraken.client.defPut
import io.icure.kraken.client.models.DelegationDto
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import java.security.*
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.concurrent.TimeUnit

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
class LocalCrypto(private val hcpartyApi: HcpartyApi, private val rsaKeyPairs: Map<String, Pair<RSAPrivateKey, RSAPublicKey>>) : Crypto {
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
        return keys[myId]?.mapNotNull { d ->
            try {
                getDelegateHcPartyKey(d.delegatedTo!!, d.owner!!)
            } catch (e: Exception) {
                null
            }?.let { k -> decryptAES(d.key!!.keyFromHexString(), k).toString(Charsets.UTF_8)
                .split(":")[1]
            }
        }?.toSet() ?: throw IllegalArgumentException("Missing key for $myId")
    }

    override suspend fun encryptKeyForHcp(myId: String, delegateId: String, objectId: String, secret: String): String {
        val secretKey = formatKey(secret)
        if (secretKey.keyFromHexString().size * 8 !in aesValidKeySizes) {
            throw IllegalArgumentException("Illegal AES key size : Secret length should be either 128, 192 or 256")
        }
        return encryptAES("$objectId:${formatKey(secret)}".toByteArray(Charsets.UTF_8), getOrCreateHcPartyKey(myId, delegateId)).keyToHexString()
    }

    private fun formatKey(key: String) : String {
        return try {
            UUID.fromString(key).let { key.replace("-", "") }
        } catch (e : IllegalArgumentException) {
            key
        }
    }

    suspend fun getDelegateHcPartyKey(delegateId: String, ownerId: String, myPrivateKey: PrivateKey? = null): ByteArray {
        val privateKey = myPrivateKey ?: rsaKeyPairs[delegateId]?.first ?: throw IllegalArgumentException("Missing key for hcp $delegateId")
        val keyMap: Map<String, Pair<String, ByteArray>> =
            delegateHcpartyKeysCache.defGet(delegateId) {
                hcpartyApi.getHcPartyKeysForDelegate(delegateId)?.decryptHcPartyKeys(delegateId, privateKey)
            } ?: throw IllegalArgumentException("Unknown hcp $delegateId")

        return keyMap[ownerId]?.second ?: throw IllegalArgumentException("Missing share for $ownerId")
    }

    suspend fun getOrCreateHcPartyKey(myId: String, delegateId: String, privateKey: PrivateKey? = null, publicKey: PublicKey? = null): ByteArray {
        val myPublicKey = publicKey ?: rsaKeyPairs[myId]?.second ?: throw IllegalArgumentException("Missing key for hcp $myId")
        val myPrivateKey = privateKey ?: rsaKeyPairs[myId]?.first ?: throw IllegalArgumentException("Missing key for hcp $myId")
        val keyMap: Map<String, Pair<String, ByteArray>> =
            ownerHcpartyKeysCache.defGet(myId) {
                hcpartyApi.getHealthcareParty(myId)?.hcPartyKeys?.mapValues { (_, v) -> v[0] }?.decryptHcPartyKeys(myId, myPrivateKey)
            } ?: throw IllegalArgumentException("Unknown hcp $myId")

        return keyMap[delegateId]?.second ?: CryptoUtils.generateKeyAES().encoded.let {
            val keyForMe = CryptoUtils.encryptRSA(it, myPublicKey).keyToHexString()
            val keyForDelegate = CryptoUtils.encryptRSA(
                        it,
                        hcpartyApi.getHealthcareParty(delegateId)?.publicKey?.let { pk ->
                            KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(pk.keyFromHexString()))
                        } ?: throw IllegalArgumentException("Unknown hcp $delegateId")
                    ).keyToHexString()
            hcpartyApi.getHealthcareParty(myId)?.let { hcp ->
                ownerHcpartyKeysCache.defPut(myId) {
                    hcpartyApi.modifyHealthcareParty(
                        hcp.copy(
                            hcPartyKeys = hcp.hcPartyKeys + (delegateId to listOf(
                                keyForMe,
                                keyForDelegate
                            ))
                        )
                    )?.hcPartyKeys?.mapValues { (_, v) -> v[0] }?.decryptHcPartyKeys(myId, myPrivateKey)
                        ?: throw IllegalStateException("Cannot save new hcparty keys in hcp $myId")
                }
            } ?: throw IllegalArgumentException("Unknown hcp $myId")
            it
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
