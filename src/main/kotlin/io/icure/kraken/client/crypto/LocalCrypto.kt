package io.icure.kraken.client.crypto

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import io.icure.kraken.client.applyIf
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
import java.security.KeyPair
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
    private val rsaKeyPairs: Map<String, List<Pair<RSAPrivateKey, RSAPublicKey>>>
) : Crypto {
    private val aesValidKeySizes : Set<Int> = setOf(128, 192, 256)

    private val ownerHcpartyKeysCache : Cache<String, Deferred<Optional<Map<String, Map<String, Pair<String, ByteArray>>>>>> = Caffeine.newBuilder()
        .maximumSize(100)
        .expireAfterWrite(5, TimeUnit.MINUTES)
        .build()
    private val delegateHcpartyKeysCache : Cache<String, Deferred<Optional<Map<String, Map<String, Map<String, Pair<String, ByteArray>>>>>>> = Caffeine.newBuilder()
        .maximumSize(100)
        .expireAfterWrite(5, TimeUnit.MINUTES)
        .build()

    override suspend fun decryptEncryptionKeys(myId: String, keys: Map<String, Set<DelegationDto>>): Set<String> {
        return ((keys[myId]?.flatMap { d ->
            getDelegateHcPartyKeys(d.delegatedTo!!, d.owner!!)
                .mapNotNull { k ->
                    try {
                        decryptAES(d.key!!.keyFromHexString(), k)
                            .toString(Charsets.UTF_8)
                            .split(":")[1]
                    } catch (e: Exception) {
                        null
                    }
                }
        }?.toSet() ?: emptySet()) + (dataOwnerResolver.getDataOwner(myId).parentId?.let { decryptEncryptionKeys(it, keys) } ?: emptySet()))
            .takeIf { it.isNotEmpty() } ?: throw IllegalArgumentException("Missing key for $myId")
    }

    override suspend fun encryptAESKeyForDataOwner(myId: String, delegateId: String, objectId: String, secret: String): Pair<String, DataOwner?> {
        val secretKey = formatKey(secret)
        if (secretKey.keyFromHexString().size * 8 !in aesValidKeySizes) {
            throw IllegalArgumentException("Illegal AES key size : Secret length should be either 128, 192 or 256")
        }
        val (keys, dataOwner) = getOrCreateAesExchangeKeys(myId, delegateId) //TODO Really the first one ?
        return encryptAES("$objectId:$secretKey".toByteArray(Charsets.UTF_8), keys.first()).keyToHexString() to dataOwner
    }

    override suspend fun encryptValueForDataOwner(myId: String, delegateId: String, objectId: String, secret: String): Pair<String, DataOwner?> {
        val (keys, dataOwner) = getOrCreateAesExchangeKeys(myId, delegateId)
        return encryptAES("$objectId:$secret".toByteArray(Charsets.UTF_8), keys.first()).keyToHexString() to dataOwner
    }

    private fun formatKey(key: String) : String {
        return try {
            UUID.fromString(key).let { key.replace("-", "") }
        } catch (e : IllegalArgumentException) {
            key
        }
    }

    private fun getOwnerIdDelegateIdKeyForCache(delegatorId: String, delegateId: String): String {
        return "$delegatorId:$delegateId"
    }

    private suspend fun getDelegateHcPartyKeys(delegateId: String, ownerId: String): List<ByteArray> {
        val rsaKeyPairs = rsaKeyPairs[delegateId] ?: throw MissingPrivateKeyException(delegateId, "Missing key(s) for data owner $delegateId")
        val delegateIdOwnerIdKey = getOwnerIdDelegateIdKeyForCache(delegateId = delegateId, delegatorId = ownerId)

        val keyMap: Map<String, Map<String, Map<String, Pair<String, ByteArray>>>> =
            delegateHcpartyKeysCache.defGet(delegateIdOwnerIdKey) {
                dataOwnerResolver.getDataOwnerHcPartyKeysForDelegate(delegateId).decryptAesExchangeKeysFor(delegateId, rsaKeyPairs)
            } ?: throw IllegalArgumentException("Unknown data owner $delegateId")

        return keyMap[ownerId]?.flatMap { (_, keys) ->
            keys.mapNotNull { (_, decryptedKey) -> decryptedKey.second }
        } ?: throw IllegalArgumentException("Missing share for $ownerId")
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

    private suspend fun getDataOwnerHcPartyKeys(dataOwnerId: String, dataOwnerPublicKeys: List<String>) =
        dataOwnerResolver.getDataOwner(dataOwnerId).findRelatedHcPartyKeys(dataOwnerPublicKeys)

    private suspend fun getOrCreateAesExchangeKeys(myId: String, delegateId: String): Pair<List<ByteArray>, DataOwner?> { //TODO We should send back a Map<String, Pair<ByteArray, ...>> to send back all possible decrypted keys (in argument, we receive all pubKeys of the myId as well)
        val ownerIdDelegateIdKey = getOwnerIdDelegateIdKeyForCache(delegateId = delegateId, delegatorId = myId)

        val myKeyPairs = rsaKeyPairs[myId] ?: throw IllegalArgumentException("Missing key for data owner $myId")
        val myPublicKeys = rsaKeyPairs[myId]?.map { it.second } ?: throw IllegalArgumentException("Missing key for data owner $myId")

        // MMmh...
        val keyMap: Map<String, Map<String, Pair<String, ByteArray>>> =
            ownerHcpartyKeysCache.defGet(ownerIdDelegateIdKey) {
                getDataOwnerHcPartyKeys(myId, myPublicKeys.map { it.pubKeyAsString() }).decryptAesExchangeKeysFor(myKeyPairs)
            } ?: throw IllegalArgumentException("Unknown hcp $myId")

        val existingAesExchangeKeysForDataOwner: Pair<List<ByteArray>, DataOwner?> = myPublicKeys.mapNotNull { myPubKey ->
            keyMap[myPubKey.pubKeyAsString()]?.get(delegateId)?.second
        }.let { it to null }

        if (existingAesExchangeKeysForDataOwner.first.isNotEmpty()) {
            return existingAesExchangeKeysForDataOwner
        }

        val allNewAesExchangeKeys = myPublicKeys.map { myPubKey ->
            val aesKey = CryptoUtils.generateKeyAES().encoded
            val keyForMe = myPubKey.pubKeyAsString() to CryptoUtils.encryptRSA(aesKey, myPubKey).keyToHexString()
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

            Triple(aesKey, keyForMe, keysForDelegate)
        }

        val dataOwnerNewAesExchangeKeys = allNewAesExchangeKeys.associate { (_, keyForMe, keysForDelegates) ->
            keyForMe.first to (delegateId to keysForDelegates)
        }

        return allNewAesExchangeKeys.map { (aesKey, _, _) -> aesKey } to dataOwnerResolver.getDataOwner(myId).let { dataOwner ->
            CoroutineScope(Dispatchers.IO).async {
                dataOwnerResolver.updateDataOwnerWithNewHcPartyKeys(
                    dataOwner.type,
                    dataOwner.dataOwnerId,
                    dataOwnerNewAesExchangeKeys
                )
            }.also { deferredNewDataOwner ->
                ownerHcpartyKeysCache.defPut(ownerIdDelegateIdKey) {
                    deferredNewDataOwner.await().findRelatedHcPartyKeys(myPublicKeys.map { it.pubKeyAsString() })
                        .decryptAesExchangeKeysFor(myKeyPairs)
                }
            }
        }.await()
    }

    override suspend fun addNewKeyPairTo(dataOwnerId: String,
                                         newPubKey: PublicKey,
                                         newPrivateKey: PrivateKey?
    ) : DataOwner = addNewKeyPairTo(dataOwnerResolver.getDataOwner(dataOwnerId), newPubKey, newPrivateKey)

    override suspend fun addNewKeyPairTo(dataOwner: DataOwner, newPubKey: PublicKey, newPrivateKey: PrivateKey?) : DataOwner {
        val aesKey = CryptoUtils.generateKeyAES().encoded
        val newAesExchangeKey = encryptAesKeyFor(dataOwner, aesKey, newPubKey)

        //TODO Send MaintenanceTasks

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

                dataOwner.updateAesExchangeKeys(mapOf(newAesExchangeKey))
                    .copy(transferKeys = mutableTransferKeys.toMap())

            } ?: dataOwner.updateAesExchangeKeys(mapOf(newAesExchangeKey))
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

    /** Decrypt aesExchangeKeys
     *
     */
    private fun Map<String, Map<String, String>>.decryptAesExchangeKeysFor(
        myKeyPairs: List<Pair<RSAPrivateKey, RSAPublicKey>>
    ) = this.mapNotNull { (pubKey, aesExchangeKeys) ->
        val correspondingPrivKey = myKeyPairs.find { (_, myPubKey) -> myPubKey.pubKeyAsString().takeLast(12) == pubKey.takeLast(12) }
            ?.first

        correspondingPrivKey?.let { myPrivKey ->
            pubKey to aesExchangeKeys.mapValues { (_, encKey) ->
                encKey to CryptoUtils.decryptRSA(encKey.keyFromHexString(), myPrivKey)
            }
        }
    }.applyIf({ it.isEmpty() }) {
        throw IllegalArgumentException("Could not decrypt any aesExchangeKeys with provided keyPairs")
    }.toMap()

    private fun Map<String, Map<String, Map<String, String>>>.decryptAesExchangeKeysFor(
        myId: String,
        myKeyPairs: List<Pair<PrivateKey, PublicKey>>
    ) : Map<String, Map<String, Map<String, Pair<String, ByteArray>>>> {
        val cachedKeys = mutableMapOf<String, PrivateKey?>()
        return this.map { (delegatorId, delegatorKeys) ->
            delegatorId to delegatorKeys.map { (slicedDelegatorPubKey, aesExchangeKeys) ->
                slicedDelegatorPubKey to aesExchangeKeys.mapNotNull { (delegatePubKey, encKey) ->
                    // If we have the delegatePubKey info, we may directly choose the appropriate key in myKeyPairs
                    if (delegatePubKey.isNotBlank()) {
                        cachedKeys.computeIfAbsent(delegatePubKey) {
                            myKeyPairs.find { it.second.pubKeyAsString().takeLast(12) == delegatePubKey }?.first
                        }

                        cachedKeys[delegatePubKey]?.let { myPrivateKey ->
                            try {
                                slicedDelegatorPubKey to (encKey to CryptoUtils.decryptRSA(encKey.keyFromHexString(), myPrivateKey))
                            } catch (exception: Exception) {
                                null
                            }
                        }
                    } else {
                        // Otherwise, we need to test them all, and take the first one working
                        myKeyPairs.mapFirstNotNull { (privKey, _) ->
                            try {
                                slicedDelegatorPubKey to (encKey to CryptoUtils.decryptRSA(encKey.keyFromHexString(), privKey))
                            } catch (exception: Exception) {
                                null
                            }
                        }
                    }
                }.applyIf({ it.isEmpty() }) {
                    throw IllegalArgumentException("Invalid HCP key for hcp $myId")
                }.toMap()
            }.toMap()
        }.toMap()

    }

    private fun Map<String, Map<String, Map<String, String>>>.decryptAesExchangeKeyFor(
        myId: String,
        myPrivateKey: PrivateKey
    ) = this
        .map { (delegatorId, delegatorKeys) ->
            delegatorId to delegatorKeys.map { (slicedDelegatorPubKey, aesExchangeKeysValues) ->
                slicedDelegatorPubKey to aesExchangeKeysValues.values.toList()
            }.associate { (slicedDelegatorPubKey, aesExchangeKeysValues) ->
                aesExchangeKeysValues.mapFirstNotNull { v ->
                    try {
                        slicedDelegatorPubKey to (v to CryptoUtils.decryptRSA(v.keyFromHexString(), myPrivateKey))
                    } catch (exception: Exception) {
                        null
                    }
                } ?: throw IllegalArgumentException("Invalid HCP key for hcp $myId")
            }
        }.toMap()
}
