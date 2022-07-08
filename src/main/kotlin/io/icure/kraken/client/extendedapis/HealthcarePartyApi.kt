package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.applyIf
import io.icure.kraken.client.crypto.Crypto
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.keyFromHexString
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
    return this.getCurrentHealthcareParty().let { currentHcp ->
        listOfNotNull(
            this.getHealthcareParty(delegateId).let { delegateHcpToMigrate ->
                this.migrateToMultipleKeys(delegateHcpToMigrate, localCrypto).let { migratedHcp ->
                    this.modifyHealthcareParty(
                        migratedHcp.copy(
                            aesExchangeKeys = migratedHcp.aesExchangeKeys.entries.fold(migratedHcp.aesExchangeKeys.toPersistentMap()) { acc, (pubKey, hcPartyKeys) ->
                                val hcPartyKeysForCurrentHcp = hcPartyKeys[currentHcp.id]

                                hcPartyKeysForCurrentHcp?.get(specificKeyPair.second.pubKeyAsString().takeLast(32))?.let {
                                    CryptoUtils.decryptRSA(it.keyFromHexString(), specificKeyPair.first)
                                }?.let {
                                    hcPartyKeysForCurrentHcp.toPersistentMap().put(delegatePublicKey.pubKeyAsString().takeLast(32), CryptoUtils.encryptRSA(it, delegatePublicKey).keyToHexString())
                                }?.let {
                                    hcPartyKeys.toPersistentMap().put(currentHcp.id, it)
                                }?.let {
                                    acc.put(pubKey, it)
                                } ?: acc
                            }
                        )
                    )
                }
            },
            this.migrateToMultipleKeys(currentHcp, localCrypto).let { migratedCurrentHcp ->
                migratedCurrentHcp.aesExchangeKeys.toPersistentMap().let { aesExchangeKeys ->
                    specificKeyPair.second.pubKeyAsString().let { pubKeyString ->
                        (aesExchangeKeys[pubKeyString] ?: throw IllegalStateException("Couldn't find HcPartyKeys for pubKey: $pubKeyString")).toPersistentMap().let { hcPartyKeys ->
                            hcPartyKeys[delegateId]?.toPersistentMap()?.let { delegateHcPartyKeys ->
                                this.modifyHealthcareParty(
                                    migratedCurrentHcp.copy(
                                        aesExchangeKeys = delegateHcPartyKeys[specificKeyPair.second.pubKeyAsString().takeLast(32)]?.let {
                                            CryptoUtils.decryptRSA(it.keyFromHexString(), specificKeyPair.first)
                                        }?.let {
                                            delegateHcPartyKeys.put(delegatePublicKey.pubKeyAsString().takeLast(32), CryptoUtils.encryptRSA(it, delegatePublicKey).keyToHexString())
                                        }?.let {
                                            hcPartyKeys.put(delegateId, it)
                                        }?.let {
                                            aesExchangeKeys.put(specificKeyPair.second.pubKeyAsString(), it)
                                        } ?: aesExchangeKeys
                                    )
                                )
                            }
                        }
                    }
                }
            }
        )
    }
}

@OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class, FlowPreview::class, ExperimentalUnsignedTypes::class)
private suspend fun HealthcarePartyApi.migrateToMultipleKeys(hcPartyDto: HealthcarePartyDto, localCrypto: LocalCrypto): HealthcarePartyDto{
    if (hcPartyDto.aesExchangeKeys.isNotEmpty()) {
        return hcPartyDto
    } else {
        val publicKey = hcPartyDto.publicKey!!
        val delegatePublicKeys = hcPartyDto.hcPartyKeys.keys.map { delegateId ->
            flow { emit(delegateId to localCrypto.getDataOwnerPublicKeys(delegateId)) }
        }.asFlow().flattenMerge().toList()

        return this.modifyHealthcareParty(
            hcPartyDto.copy(
                aesExchangeKeys = mapOf(
                    publicKey to hcPartyDto.hcPartyKeys.entries.associate { (delegateId, hcPartyKeys) ->
                        delegateId to mapOf(
                            publicKey.takeLast(32) to hcPartyKeys[0],
                            delegatePublicKeys.first { it.first === delegateId }.second.first().first.takeLast(32) to hcPartyKeys[1]
                        )
                    }
                )
            )
        )
    }
}
