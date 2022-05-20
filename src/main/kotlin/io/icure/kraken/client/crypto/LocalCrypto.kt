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
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.concurrent.TimeUnit

@OptIn(ExperimentalUnsignedTypes::class)
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

    private fun getOwnerIdDelegateIdKeyForCache(ownerId: String, delegateId: String): String {
        return "$ownerId:$delegateId"
    }

    private suspend fun getDelegateHcPartyKey(delegateId: String, ownerId: String, myPrivateKey: PrivateKey? = null): ByteArray {
        val delegateIdOwnerIdKey = getOwnerIdDelegateIdKeyForCache(delegateId = delegateId, ownerId = ownerId)
        val privateKey = myPrivateKey ?: rsaKeyPairs[delegateId]?.first ?: throw MissingPrivateKeyException(delegateId, "Missing key for data owner $delegateId")
        val keyMap: Map<String, Pair<String, ByteArray>> =
            delegateHcpartyKeysCache.defGet(delegateIdOwnerIdKey) {
                dataOwnerResolver.getDataOwnerHcPartyKeysForDelegate(delegateId).decryptAesExchangeKeyFor(delegateId, privateKey)
            } ?: throw IllegalArgumentException("Unknown data owner $delegateId")

        return keyMap[ownerId]?.second ?: throw IllegalArgumentException("Missing share for $ownerId")
    }

    /**
     * @return all the Public Keys known for the provided Data Owner Id. Returns first the "main" publicKey of the
     * dataOwner and the ones contained on the aesExchangeKeys afterwards
     */
    private suspend fun getDataOwnerPublicKeys(dataOwnerId: String) : List<Pair<String, PublicKey>> {
        return getDataOwnerPublicKeys(dataOwnerResolver.getDataOwner(dataOwnerId))
    }

    /**
     * @return all the Public Keys known for the provided Data Owner Id. Returns first the "main" publicKey of the
     * dataOwner and the ones contained on the aesExchangeKeys afterwards
     */
    private fun getDataOwnerPublicKeys(dataOwner: DataOwner) : List<Pair<String, PublicKey>> {
        return (listOf(dataOwner.publicKey).plus(dataOwner.aesExchangeKeys.keys).distinct())
            .filterNotNull()
            .map { pubKey ->
                pubKey to KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(pubKey.keyFromHexString()))
            }
    }

    private suspend fun getDataOwnerHcPartyKeys(dataOwnerId: String, dataOwnerPublicKey: String) =
        dataOwnerResolver.getDataOwner(dataOwnerId).findRelatedHcPartyKeys(dataOwnerPublicKey)

    private suspend fun getOrCreateHcPartyKey(myId: String, delegateId: String, privateKey: PrivateKey? = null, publicKey: PublicKey? = null): Pair<ByteArray, DataOwner?> {
        val ownerIdDelegateIdKey = getOwnerIdDelegateIdKeyForCache(delegateId = delegateId, ownerId = myId)
        val myPublicKey = publicKey ?: rsaKeyPairs[myId]?.second ?: throw IllegalArgumentException("Missing key for data owner $myId")
        val myPrivateKey = privateKey ?: rsaKeyPairs[myId]?.first ?: throw MissingPrivateKeyException(myId, "Missing key for data owner $myId")
        val keyMap: Map<String, Pair<String, ByteArray>> =
            ownerHcpartyKeysCache.defGet(ownerIdDelegateIdKey) {
                getDataOwnerHcPartyKeys(myId, myPublicKey.pubKeyAsString()).decryptHcPartyKeys(myPrivateKey)
            } ?: throw IllegalArgumentException("Unknown hcp $myId")

        return keyMap[delegateId]?.second?.let { it to null } ?: CryptoUtils.generateKeyAES().encoded.let { aesKey ->
            val keyForMe = CryptoUtils.encryptRSA(aesKey, myPublicKey).keyToHexString()
            val keysForDelegate = getDataOwnerPublicKeys(delegateId)
                .map { (rawPubKey, pubKey) ->
                    rawPubKey to CryptoUtils.encryptRSA(
                        aesKey,
                        pubKey
                    ).keyToHexString()
                }
            if (keysForDelegate.isEmpty()) {
                throw IllegalArgumentException("Unknown hcp $delegateId")
            }

            aesKey to dataOwnerResolver.getDataOwner(myId).let { hcp ->
                CoroutineScope(Dispatchers.IO).async {
                    dataOwnerResolver.updateDataOwnerWithNewHcPartyKeys(
                        hcp.type, hcp.dataOwnerId, (myPublicKey.pubKeyAsString() to (delegateId to (listOf(myPublicKey.pubKeyAsString() to keyForMe) + keysForDelegate)))
                    )
                }.also { deferredNewDataOwner ->
                    ownerHcpartyKeysCache.defPut(ownerIdDelegateIdKey) {
                        deferredNewDataOwner.await().findRelatedHcPartyKeys(myPublicKey.pubKeyAsString())
                            .decryptHcPartyKeys(myPrivateKey)
                    }
                }
            }.await()
        }
    }

    override suspend fun addNewKeyPairTo(dataOwnerId: String,
                                         newPubKey: PublicKey,
                                         newPrivateKey: PrivateKey?
    ) : DataOwner = addNewKeyPairTo(dataOwnerResolver.getDataOwner(dataOwnerId), newPubKey, newPrivateKey)

    override suspend fun addNewKeyPairTo(dataOwner: DataOwner, newPubKey: PublicKey, newPrivateKey: PrivateKey?) : DataOwner {
        val aesKey = CryptoUtils.generateKeyAES().encoded
        val newAesExchangeKey = encryptAesKeyFor(dataOwner, aesKey, newPubKey)

        //TODO Send SharingTasks

        return getDataOwnerPublicKeys(dataOwner)
            .takeIf { existingPublicKeys -> existingPublicKeys.isNotEmpty() && newPrivateKey != null}
            ?.let { existingPublicKeys ->
                val newTransferKey = encryptAES(newPrivateKey!!.encoded, aesKey).keyToHexString()
                val mutableTransferKeys = dataOwner.transferKeys.toMutableMap()

                existingPublicKeys
                    .map { (pubKey, _) -> pubKey }
                    .forEach { pubKey ->
                        mutableTransferKeys.merge(
                            pubKey,
                            mapOf(newAesExchangeKey.first to newTransferKey)
                        ) { previousKeys, newKeys ->
                            previousKeys + newKeys
                        }
                    }

                dataOwner.updateAesExchangeKeys(newAesExchangeKey)
                    .copy(transferKeys = mutableTransferKeys.toMap())

            } ?: dataOwner.updateAesExchangeKeys(newAesExchangeKey)
    }

    private fun encryptAesKeyFor(
        dataOwner: DataOwner,
        aesKey: ByteArray,
        myPublicKey: PublicKey
    ): Pair<String, Pair<String, List<Pair<String, String>>>> {
        val keyForMe = CryptoUtils.encryptRSA(aesKey, myPublicKey).keyToHexString()
        val keysForDelegate = (listOf(myPublicKey.pubKeyAsString() to myPublicKey) + getDataOwnerPublicKeys(dataOwner))
            .map { (rawPubKey, pubKey) ->
                rawPubKey to CryptoUtils.encryptRSA(
                    aesKey,
                    pubKey
                ).keyToHexString()
            }
            .ifEmpty {
                throw IllegalArgumentException("Unknown data owner ${dataOwner.dataOwnerId}")
            }

        return myPublicKey.pubKeyAsString() to (dataOwner.dataOwnerId to (listOf(myPublicKey.pubKeyAsString() to keyForMe) + keysForDelegate))
    }

    /** Decrypt hcparty keys
     *
     */
    private fun Map<String, String>.decryptHcPartyKeys(
        myPrivateKey: PrivateKey
    ) = this.mapValues { (_, v) ->
        v to CryptoUtils.decryptRSA(v.keyFromHexString(), myPrivateKey)
    }

    private fun Map<String, Map<String, String>>.decryptAesExchangeKeyFor(
        myId: String,
        myPrivateKey: PrivateKey
    ) = this
        .map { (key, hcPartyKeysValues) ->
            key to hcPartyKeysValues.values.toList()
        }.associate { (key, hcPartyKeysValues) ->
            hcPartyKeysValues.mapFirstNotNull { v ->
                try {
                    key to (v to CryptoUtils.decryptRSA(v.keyFromHexString(), myPrivateKey))
                } catch (exception: Exception) {
                    null
                }
            } ?: throw IllegalArgumentException("Invalid HCP key for hcp $myId")
        }
}
