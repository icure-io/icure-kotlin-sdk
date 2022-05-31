package io.icure.kraken.client.crypto

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import io.icure.kraken.client.apis.MaintenanceTaskApi
import io.icure.kraken.client.applyIf
import io.icure.kraken.client.crypto.CryptoUtils.decryptAES
import io.icure.kraken.client.crypto.CryptoUtils.encryptAES
import io.icure.kraken.client.defGet
import io.icure.kraken.client.defPut
import io.icure.kraken.client.exception.MissingPrivateKeyException
import io.icure.kraken.client.extendedapis.DataOwner
import io.icure.kraken.client.extendedapis.DataOwnerResolver
import io.icure.kraken.client.extendedapis.createMaintenanceTask
import io.icure.kraken.client.models.DelegationDto
import io.icure.kraken.client.models.PropertyStubDto
import io.icure.kraken.client.models.PropertyTypeStubDto
import io.icure.kraken.client.models.TypedValueDtoObject
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.MaintenanceTaskDto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.flatMapMerge
import kotlinx.coroutines.flow.flattenMerge
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.onEmpty
import kotlinx.coroutines.flow.transformLatest
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
    private val rsaKeyPairs: Map<String, List<Pair<RSAPrivateKey, RSAPublicKey>>>,
    private val maintenanceTaskApi: MaintenanceTaskApi? = null
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
            getDelegateAesExchangeKeys(d.delegatedTo!!, d.owner!!)
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

    private suspend fun getDelegateAesExchangeKeys(delegateId: String, ownerId: String): List<ByteArray> {
        val rsaKeyPairs = rsaKeyPairs[delegateId] ?: throw MissingPrivateKeyException(delegateId, "Missing key(s) for data owner $delegateId")
        val delegateIdOwnerIdKey = getOwnerIdDelegateIdKeyForCache(delegateId = delegateId, delegatorId = ownerId)

        val keyMap: Map<String, Map<String, Map<String, Pair<String, ByteArray>>>> =
            delegateHcpartyKeysCache.defGet(delegateIdOwnerIdKey) {
                dataOwnerResolver.getDataOwnerAesExchangeKeysForDelegate(delegateId).decryptAesExchangeKeysFor(delegateId, rsaKeyPairs)
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

    private suspend fun getDataOwnerAesExchangeKeys(dataOwnerId: String, dataOwnerPublicKeys: List<String>) =
        dataOwnerResolver.getDataOwner(dataOwnerId).findRelatedAesExchangeKeys(dataOwnerPublicKeys)

    private suspend fun getOrCreateAesExchangeKeys(myId: String, delegateId: String): Pair<List<ByteArray>, DataOwner?> { //TODO We should send back a Map<String, Pair<ByteArray, ...>> to send back all possible decrypted keys (in argument, we receive all pubKeys of the myId as well)
        val ownerIdDelegateIdKey = getOwnerIdDelegateIdKeyForCache(delegateId = delegateId, delegatorId = myId)

        val myKeyPairs = rsaKeyPairs[myId] ?: throw IllegalArgumentException("Missing key for data owner $myId")
        val myPublicKeys = rsaKeyPairs[myId]?.map { it.second } ?: throw IllegalArgumentException("Missing key for data owner $myId")

        val keyMap: Map<String, Map<String, Pair<String, ByteArray>>> =
            ownerHcpartyKeysCache.defGet(ownerIdDelegateIdKey) {
                getDataOwnerAesExchangeKeys(myId, myPublicKeys.map { it.pubKeyAsString() }).decryptAesExchangeKeysFor(myKeyPairs)
            } ?: throw IllegalArgumentException("Unknown hcp $myId")

        val existingAesExchangeKeysForDataOwner: Pair<List<ByteArray>, DataOwner?> = myPublicKeys.mapNotNull { myPubKey ->
            keyMap[myPubKey.pubKeyAsString()]?.get(delegateId)?.second
        }.let { it to null }

        if (existingAesExchangeKeysForDataOwner.first.isNotEmpty()) {
            return existingAesExchangeKeysForDataOwner
        }

        val aesKey = CryptoUtils.generateKeyAES().encoded
        val keyForMe = myPublicKeys.first().let { myPubKey -> // As keys are protected and accessible in transferKeys, no need to encrypt with all of them
            myPubKey.pubKeyAsString() to CryptoUtils.encryptRSA(
                aesKey,
                myPubKey
            ).keyToHexString()
        }
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

        val dataOwnerNewAesExchangeKeys = keyForMe.first to (delegateId to (listOf(keyForMe) + keysForDelegate))

        return listOf(aesKey) to dataOwnerResolver.getDataOwner(myId).let { dataOwner ->
            CoroutineScope(Dispatchers.IO).async {
                dataOwnerResolver.updateDataOwnerWithNewAesExchangeKeys(
                    dataOwner.type,
                    dataOwner.dataOwnerId,
                    dataOwnerNewAesExchangeKeys.first,
                    dataOwnerNewAesExchangeKeys.second
                )
            }.also { deferredNewDataOwner ->
                ownerHcpartyKeysCache.defPut(ownerIdDelegateIdKey) {
                    deferredNewDataOwner.await().findRelatedAesExchangeKeys(myPublicKeys.map { it.pubKeyAsString() })
                        .decryptAesExchangeKeysFor(myKeyPairs)
                }
            }
        }.await()
    }

    override suspend fun addNewKeyPairTo(user: UserDto,
                                         dataOwnerId: String,
                                         newPubKey: PublicKey,
                                         newPrivateKey: PrivateKey?
    ) : DataOwner = addNewKeyPairTo(user, dataOwnerResolver.getDataOwner(dataOwnerId), newPubKey, newPrivateKey)

    override suspend fun addNewKeyPairTo(user: UserDto, dataOwner: DataOwner, newPubKey: PublicKey, newPrivateKey: PrivateKey?) : DataOwner {
        val dataOwnerToUpdate = sendMaintenanceTasksForDataOwner(user, dataOwner, newPubKey)
            .onEach { createdMaintenanceTask ->
                println("Created MaintenanceTask $createdMaintenanceTask for data owner ${dataOwner.dataOwnerId}")
            }.firstOrNull()
            ?.let { dataOwnerResolver.getDataOwner(dataOwner.dataOwnerId) }
            ?: dataOwner

        return updateDataOwnerWithNewKeys(dataOwnerToUpdate, newPubKey, newPrivateKey)
    }

    private fun updateDataOwnerWithNewKeys(
        dataOwner: DataOwner,
        newPubKey: PublicKey,
        newPrivateKey: PrivateKey?
    ) : DataOwner {
        val aesKey = CryptoUtils.generateKeyAES().encoded
        val newAesExchangeKey = encryptAesKeyFor(dataOwner, aesKey, newPubKey)

        return getDataOwnerPublicKeys(dataOwner)
            .takeIf { existingPublicKeys -> existingPublicKeys.isNotEmpty() && newPrivateKey != null }
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

                dataOwner.updateAesExchangeKeys(newAesExchangeKey.first, newAesExchangeKey.second)
                    .copy(transferKeys = mutableTransferKeys.toMap())

            } ?: dataOwner.updateAesExchangeKeys(newAesExchangeKey.first, newAesExchangeKey.second)
    }

    private suspend fun sendMaintenanceTasksForDataOwner(user: UserDto, dataOwner: DataOwner, newPubKey: PublicKey) : Flow<MaintenanceTaskDto> {
        if (maintenanceTaskApi == null) {
            throw IllegalStateException("MaintenanceTaskApi is not initialized !")
        }

        val nonAccessiblePublicKeys = getDataOwnerPublicKeys(dataOwner)
            .filterNot { (rawPubKey, _) -> rawPubKey == newPubKey.pubKeyAsString() }
            .filter { (rawPubKey, _) -> (rsaKeyPairs[dataOwner.dataOwnerId]?.find { (_, pubKey) -> rawPubKey == pubKey.pubKeyAsString() } == null) }

        if (nonAccessiblePublicKeys.isNotEmpty()) {
            try {
                val nonAccessibleDelegateAesExchangeKeys =
                    dataOwnerResolver.getDataOwnerAesExchangeKeysForDelegate(dataOwner.dataOwnerId)
                        .filter { (delegatorId, _) -> delegatorId != dataOwner.dataOwnerId }
                        .flatMap { (delegatorId, delegatorKeys) ->
                            delegatorKeys.flatMap { (_, aesExchangeKeys) ->
                                aesExchangeKeys.map { (delegatePubKey, _) ->
                                    delegatorId to createMaintenanceTaskFor(dataOwner, delegatePubKey)
                                }
                            }
                        }.asFlow()

                val nonAccessibleDelegatorAesExchangeKeys =
                    dataOwner.findRelatedAesExchangeKeys(nonAccessiblePublicKeys.map { (rawPubKey, _) -> rawPubKey })
                        .flatMap { (doPubKey, delegateKeys) ->
                            delegateKeys
                                .filter { (delegateId, _) -> delegateId != dataOwner.dataOwnerId }
                                .map { (delegateId, _) ->
                                    delegateId to createMaintenanceTaskFor(dataOwner, doPubKey)
                                }
                        }.asFlow()

                val maintenanceTaskCc = maintenanceTaskCryptoConfig(this@LocalCrypto, user)

                return flowOf(nonAccessibleDelegateAesExchangeKeys, nonAccessibleDelegatorAesExchangeKeys)
                    .flattenMerge(10)
                    .map { (delegateId, newMaintenanceTask) ->
                        maintenanceTaskApi.createMaintenanceTask(
                            user,
                            newMaintenanceTask,
                            delegateId,
                            maintenanceTaskCc
                        )
                    }
            } catch (e: Exception) {
                println("Error during sending maintenance tasks $e")
                return emptyFlow()
            }
        } else {
            return emptyFlow()
        }
    }

    private fun createMaintenanceTaskFor(
        concernedDataOwner: DataOwner,
        concernedDataOwnerPubKey: String
    ) = MaintenanceTaskDto(
        id = UUID.randomUUID().toString(),
        taskType = "updateAesExchangeKey",
        status = MaintenanceTaskDto.Status.pending,
        properties = listOf(
            PropertyStubDto(
                id = "dataOwnerConcernedId",
                type = PropertyTypeStubDto(type = PropertyTypeStubDto.Type.sTRING),
                typedValue = TypedValueDtoObject(
                    type = TypedValueDtoObject.Type.sTRING,
                    stringValue = concernedDataOwner.dataOwnerId
                )
            ),
            PropertyStubDto(
                id = "dataOwnerConcernedPubKey",
                type = PropertyTypeStubDto(type = PropertyTypeStubDto.Type.sTRING),
                typedValue = TypedValueDtoObject(
                    type = TypedValueDtoObject.Type.sTRING,
                    stringValue = concernedDataOwnerPubKey
                )
            )
        )
    )

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
        val decryptedAesExchangeKeys = this.map { (delegatorId, delegatorKeys) ->
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
                }.toMap()
            }.filter { (_, keys) -> keys.isNotEmpty() }.toMap()
        }.filter { (_, keys) -> keys.isNotEmpty() }.toMap()

        return decryptedAesExchangeKeys.applyIf({ it.isEmpty() }) {
            throw IllegalArgumentException("Invalid HCP key for hcp $myId")
        }
    }
}
