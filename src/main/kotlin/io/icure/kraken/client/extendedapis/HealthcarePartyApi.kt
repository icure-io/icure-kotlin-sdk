package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.applyIf
import io.icure.kraken.client.crypto.Crypto
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.keyToHexString
import io.icure.kraken.client.crypto.pubKeyAsString
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.PersonNameDto
import io.icure.kraken.client.models.UserDto
import kotlinx.collections.immutable.toPersistentMap
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.asFlow
import kotlinx.coroutines.flow.flattenMerge
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

suspend fun HealthcarePartyDto.addNewKeyPair(user: UserDto,
                                             crypto: Crypto,
                                             hcpPublicKey: PublicKey,
                                             hcpPrivateKey: PrivateKey? = null
) = crypto.addNewKeyPairTo(user, this.toDataOwner(), hcpPublicKey, hcpPrivateKey).let { dataOwner ->
    this.copy(
        rev = dataOwner.rev,
        publicKey = dataOwner.publicKey,
        hcPartyKeys = dataOwner.hcPartyKeys,
        aesExchangeKeys = dataOwner.aesExchangeKeys,
        transferKeys = dataOwner.transferKeys
    )
}

fun HealthcarePartyDto.initHcParty() = this
    .applyIf({ hcp -> hcp.lastName == null && hcp.hasName(PersonNameDto.Use.official)}) { hcp ->
        hcp.copy(lastName = hcp.findName(PersonNameDto.Use.official)!!.lastName)
    }
    .applyIf({ hcp -> hcp.firstName == null && hcp.hasName(PersonNameDto.Use.official)}) { hcp ->
        hcp.copy(firstName = hcp.findName(PersonNameDto.Use.official)!!.firstNames.firstOrNull())
    }
    .applyIf({ hcp -> hcp.name == null && hcp.hasName(PersonNameDto.Use.official)}) { hcp ->
        hcp.copy(name = hcp.findName(PersonNameDto.Use.official)!!.text)
    }
    .applyIf({ hcp -> (hcp.lastName != null || hcp.name != null) && !hcp.hasName(PersonNameDto.Use.official)}) { hcp ->
        hcp.copy(names = hcp.names + (
                listOf(PersonNameDto(lastName = hcp.lastName, firstNames = listOfNotNull(hcp.firstName), text = hcp.name, use = PersonNameDto.Use.official))
                )
        )
    }

fun HealthcarePartyDto.hasName(nameUse: PersonNameDto.Use) : Boolean {
    return this.names.any { it.use == nameUse }
}

fun HealthcarePartyDto.findName(nameUse: PersonNameDto.Use) : PersonNameDto? {
    return this.names.find { it.use == nameUse }
}

@OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class, ExperimentalUnsignedTypes::class, FlowPreview::class)
suspend fun HealthcarePartyApi.giveAccessBack(localCrypto: LocalCrypto, specificKeyPair: Pair<RSAPrivateKey, RSAPublicKey>, delegateId: String, delegatePublicKey: PublicKey) {
    return this.getCurrentHealthcareParty().let { hcpToMigrate ->
        this.migrateToMultipleKeys(hcpToMigrate, localCrypto).let { currentHcp ->
            localCrypto.getDelegateAesExchangeKeys(delegateId, currentHcp.id, listOf(specificKeyPair)).let { aesKey ->
                CryptoUtils.encryptRSA(aesKey.firstOrNull() ?: throw IllegalStateException("Couldn't decrypt AES key for ${currentHcp.id}"), delegatePublicKey).keyToHexString().let { encryptedAesKey ->
                    currentHcp.aesExchangeKeys.toPersistentMap().let { hcpAesKeys ->
                        specificKeyPair.second.pubKeyAsString().let { pubKeyString ->
                            (hcpAesKeys[pubKeyString] ?: throw IllegalStateException("Couldn't find HcPartyKeys for pubKey: $pubKeyString")).toPersistentMap().let { hcPartyKeys ->
                                (hcPartyKeys[delegateId] ?: throw IllegalStateException("Couldn't find delegateHcPartyKeys for dataOwner $delegateId")).toPersistentMap().let { delegateHcPartyKeys ->
                                    hcpAesKeys.put(pubKeyString, hcPartyKeys.put(delegateId, delegateHcPartyKeys.put(delegatePublicKey.pubKeyAsString().takeLast(32), encryptedAesKey))).let { aesExchangeKeysToUpdate ->
                                        this.modifyHealthcareParty(
                                            currentHcp.copy(
                                                aesExchangeKeys = aesExchangeKeysToUpdate
                                            )
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class, FlowPreview::class, ExperimentalUnsignedTypes::class)
private suspend fun HealthcarePartyApi.migrateToMultipleKeys(hcPartyDto: HealthcarePartyDto, localCrypto: LocalCrypto): HealthcarePartyDto{
    if (hcPartyDto.hcPartyKeys.isEmpty() && hcPartyDto.publicKey.isNullOrEmpty()) {
        return hcPartyDto
    } else {
        val publicKey = hcPartyDto.publicKey!!
        val delegatePublicKeys = hcPartyDto.hcPartyKeys.keys.map { delegateId ->
            flow { emit(delegateId to localCrypto.getDataOwnerPublicKeys(delegateId)) }
        }.asFlow().flattenMerge().toList()

        val hcPartyToUpdate = hcPartyDto.copy(
        aesExchangeKeys = mapOf(
            publicKey to hcPartyDto.hcPartyKeys.entries.associate { (delegateId, hcPartyKeys) ->
                delegateId to mapOf(
                    publicKey.takeLast(32) to hcPartyKeys[0],
                    delegatePublicKeys.first { it.first === delegateId }.second.first().first.takeLast(32) to hcPartyKeys[1]
                )
            }
        ),
        publicKey = null,
        hcPartyKeys = emptyMap()
        )

        return this.modifyHealthcareParty(
            hcPartyToUpdate
        )
    }
}
