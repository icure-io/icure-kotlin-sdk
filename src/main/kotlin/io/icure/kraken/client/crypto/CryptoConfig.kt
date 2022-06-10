package io.icure.kraken.client.crypto

import com.fasterxml.jackson.databind.ObjectMapper
import io.icure.kraken.client.applyIf
import io.icure.kraken.client.extendedapis.ContactMapperFactory
import io.icure.kraken.client.extendedapis.DocumentMapperFactory
import io.icure.kraken.client.extendedapis.HealthElementMapperFactory
import io.icure.kraken.client.extendedapis.MaintenanceTaskMapperFactory
import io.icure.kraken.client.extendedapis.PatientMapperFactory
import io.icure.kraken.client.extendedapis.PropertyWrapper
import io.icure.kraken.client.extendedapis.dataOwnerId
import io.icure.kraken.client.extendedapis.decryptServices
import io.icure.kraken.client.extendedapis.encryptServices
import io.icure.kraken.client.infrastructure.ApiClient
import io.icure.kraken.client.models.TypedValueDtoObject
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.ContactDto
import io.icure.kraken.client.models.decrypted.DocumentDto
import io.icure.kraken.client.models.decrypted.HealthElementDto
import io.icure.kraken.client.models.decrypted.MaintenanceTaskDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import java.util.Base64

/*
D is the decrypted class, K is the crypted class
 */
open class CryptoConfig<D,K>(
    open val crypto: Crypto,
    /* The marshaller maps an instance of the decrypted class to a curated (where all sensitive fields have been set to null) instance of the crypted class
    + a ByteArray that holds the serialized information necessary to reconstruct the sensitive fields
     */
    open val marshaller: suspend (D) -> Pair<K, ByteArray>,
    /* The unmarshaller maps an instance of the crypted class to an instance of the decrypted class
    + it is responsible for deserializing the ByteArray and to reinject the sensitive fields inside the decrypted instance
     */
    val unmarshaller: suspend (K, ByteArray) -> D
)

@FlowPreview
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
fun patientCryptoConfig(crypto: LocalCrypto) =
    CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>(
        crypto = crypto,
        marshaller = { p ->
            PatientMapperFactory.instance.map(p)
                .copy(note = null) to ApiClient.objectMapper.writeValueAsBytes(mapOf("note" to p.note))
        },
        unmarshaller = { p, c ->
            PatientMapperFactory.instance.map(
                p.copy(
                    note = ApiClient.objectMapper.readTree(c).get("note")?.textValue()
                )
            )
        }
    )

@FlowPreview
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
fun maintenanceTaskCryptoConfig(crypto: LocalCrypto, user: UserDto) =
    CryptoConfig<MaintenanceTaskDto, io.icure.kraken.client.models.MaintenanceTaskDto>(
        crypto = crypto,
        marshaller = { mt ->
            if (mt.properties.isEmpty()) {
                MaintenanceTaskMapperFactory.instance.map(mt) to byteArrayOf()
            } else {
                val decryptedKey = crypto.decryptEncryptionKeys(user.dataOwnerId(), mt.encryptionKeys)
                    .firstOrNull()
                    ?.keyFromHexString() ?: throw java.lang.IllegalArgumentException("No encryption key for user ${user.id}")

                val encryptedProps = mt.properties
                    .map { prop -> prop.applyIf({ it.typedValue != null }) {
                            it.copy(
                                typedValue = null,
                                encryptedSelf = Base64.getEncoder().encodeToString(
                                    CryptoUtils.encryptAES(
                                        data = ApiClient.objectMapper.writeValueAsBytes(mapOf("typedValue" to it.typedValue)),
                                        key = decryptedKey
                                    )
                                )
                            )
                        }
                    }

                MaintenanceTaskMapperFactory.instance.map(mt.copy(properties = encryptedProps)) to byteArrayOf()
            }
        },
        unmarshaller = { mt, _ ->
            if (mt.properties.isEmpty()) {
                MaintenanceTaskMapperFactory.instance.map(mt)
            } else {
                val decryptedKey = crypto.decryptEncryptionKeys(user.dataOwnerId(), mt.encryptionKeys)
                    .firstOrNull()
                    ?.keyFromHexString() ?: throw java.lang.IllegalArgumentException("No encryption key for user ${user.id}")

                val decryptedProps = mt.properties.map { prop ->
                    prop.encryptedSelf?.let { es ->
                        prop.copy(typedValue = ApiClient.objectMapper.readValue(CryptoUtils.decryptAES(data = Base64.getDecoder().decode(es), key = decryptedKey), PropertyWrapper::class.java).typedValue)
                    } ?: prop
                }

                MaintenanceTaskMapperFactory.instance.map(mt.copy(properties = decryptedProps))
            }
        }
    )

@FlowPreview
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
fun contactCryptoConfig(
    crypto: LocalCrypto,
    user: UserDto
) = CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>(
    crypto = crypto,
    marshaller = { c ->
        val decryptedKey =
            crypto.decryptEncryptionKeys(user.dataOwnerId(), c.encryptionKeys).firstOrNull() //TODO If we have multiple keys, maybe the first one is not the preferred one for encryption. For now, we take it as an assumption
        ContactMapperFactory.instance.map(c).copy(
            services = crypto.encryptServices(
                user.dataOwnerId(),
                (user.autoDelegations["all"] ?: setOf()) + (user.autoDelegations["medicalInformation"]
                    ?: setOf()),
                decryptedKey?.toByteArray(),
                c.services
            )
        ) to byteArrayOf()
    },
    unmarshaller = { c, _ ->
        ContactMapperFactory.instance.map(c).copy(
            services = crypto.decryptServices(
                user.dataOwnerId(),
                crypto.decryptEncryptionKeys(user.dataOwnerId(), c.encryptionKeys).firstOrNull()
                    ?.toByteArray(),
                c.services
            )
        )
    }
)

@FlowPreview
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
fun healthElementCryptoConfig(
    crypto: LocalCrypto
) = CryptoConfig<HealthElementDto, io.icure.kraken.client.models.HealthElementDto>(
    crypto = crypto,
    marshaller = { c ->
        HealthElementMapperFactory.instance.map(c) to byteArrayOf()
    },
    unmarshaller = { c, b ->
        HealthElementMapperFactory.instance.map(c)
    }
)

@FlowPreview
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
fun documentCryptoConfig(
    crypto: LocalCrypto
) = CryptoConfig<DocumentDto, io.icure.kraken.client.models.DocumentDto>(
    crypto = crypto,
    marshaller = { c ->
        DocumentMapperFactory.instance.map(c) to byteArrayOf()
    },
    unmarshaller = { c, b ->
        DocumentMapperFactory.instance.map(c)
    }
)
