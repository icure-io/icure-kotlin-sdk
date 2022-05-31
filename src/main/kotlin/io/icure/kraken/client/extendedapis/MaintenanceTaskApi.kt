package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.MaintenanceTaskApi
import io.icure.kraken.client.applyIf
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.keyFromHexString
import io.icure.kraken.client.models.DelegationDto
import io.icure.kraken.client.models.TypedValueDtoObject
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.MaintenanceTaskDto
import io.icure.kraken.client.models.decrypted.PaginatedListMaintenanceTaskDto
import io.icure.kraken.client.models.filter.chain.FilterChain
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.mapstruct.Mapper
import org.mapstruct.factory.Mappers
import java.util.*

suspend fun MaintenanceTaskDto.initDelegations(user: UserDto,
                                               config: CryptoConfig<MaintenanceTaskDto, io.icure.kraken.client.models.MaintenanceTaskDto>,
                                               taskDelegatedTo: String? = null) : MaintenanceTaskDto {
    val delegations =  (taskDelegatedTo?.let { setOf(it) } ?: emptySet()) + (user.autoDelegations["all"] ?: emptySet()) + (user.autoDelegations["medicalInformation"] ?: emptySet())
    val ek = UUID.randomUUID().toString()
    val sfk = UUID.randomUUID().toString()
    return this.copy(
        responsible = user.dataOwnerId(),
        author = user.id,
        delegations = (delegations + user.dataOwnerId()).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    emptyList(), user.dataOwnerId(), d, config.crypto.encryptAESKeyForDataOwner(user.dataOwnerId(), d, this.id, sfk).first,
                ),
            ))
        },
        encryptionKeys = (delegations + user.dataOwnerId()).fold(this.encryptionKeys) { m, d ->
            m + (d to setOf(
                DelegationDto(
                    emptyList(), user.dataOwnerId(), d, config.crypto.encryptAESKeyForDataOwner(user.dataOwnerId(), d, this.id, ek).first,
                ),
            ))
        },
    )
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MaintenanceTaskApi.createMaintenanceTask(user: UserDto,
                                                     maintenanceTask: MaintenanceTaskDto,
                                                     delegatedTo: String? = null,
                                                     config: CryptoConfig<MaintenanceTaskDto, io.icure.kraken.client.models.MaintenanceTaskDto>
) = this.createMaintenanceTask(
        config.encryptMaintenanceTask(
            myId = user.dataOwnerId(),
            delegations = (delegatedTo?.let { setOf(it) } ?: emptySet()) + (user.autoDelegations["all"] ?: emptySet()) + (user.autoDelegations["medicalInformation"] ?: emptySet()),
            maintenanceTask = maintenanceTask.initDelegations(user, config, delegatedTo)
        )
    ).let { config.decryptMaintenanceTask(user.dataOwnerId(), it) }


@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MaintenanceTaskApi.filterMaintenanceTasksBy(user: UserDto,
                                                        filterChain: FilterChain<io.icure.kraken.client.models.MaintenanceTaskDto>,
                                                        startDocumentId: String? = null,
                                                        limit: Int? = null,
                                                        config: CryptoConfig<MaintenanceTaskDto, io.icure.kraken.client.models.MaintenanceTaskDto>
) : PaginatedListMaintenanceTaskDto = this.filterMaintenanceTasksBy(filterChain, startDocumentId, limit).let {
    PaginatedListMaintenanceTaskDto(rows = it.rows.map { config.decryptMaintenanceTask(user.dataOwnerId(), it) }, pageSize = it.pageSize, totalSize = it.totalSize, nextKeyPair = it.nextKeyPair)
}

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MaintenanceTaskApi.getMaintenanceTask(user: UserDto,
                                                  maintenanceTaskId: String,
                                                  config: CryptoConfig<MaintenanceTaskDto, io.icure.kraken.client.models.MaintenanceTaskDto>
) : MaintenanceTaskDto = this.getMaintenanceTask(maintenanceTaskId).let { config.decryptMaintenanceTask(user.dataOwnerId(), it) }

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
suspend fun MaintenanceTaskApi.modifyMaintenanceTask(user: UserDto,
                                                     maintenanceTask: MaintenanceTaskDto,
                                                     config: CryptoConfig<MaintenanceTaskDto, io.icure.kraken.client.models.MaintenanceTaskDto>
) = this.modifyMaintenanceTask(
    config.encryptMaintenanceTask(
        myId = user.dataOwnerId(),
        delegations = (user.autoDelegations["all"] ?: emptySet()) + (user.autoDelegations["medicalInformation"] ?: emptySet()),
        maintenanceTask = maintenanceTask
    )
).let { config.decryptMaintenanceTask(user.dataOwnerId(), it) }


// CRYPTO
suspend fun CryptoConfig<MaintenanceTaskDto, io.icure.kraken.client.models.MaintenanceTaskDto>.encryptMaintenanceTask(myId: String, delegations: Set<String>, maintenanceTask: MaintenanceTaskDto): io.icure.kraken.client.models.MaintenanceTaskDto {
    return if (maintenanceTask.encryptionKeys.any { (_,s) -> s.isNotEmpty() }) {
        maintenanceTask
    } else {
        val secret = UUID.randomUUID().toString()
        maintenanceTask.copy(encryptionKeys = (delegations + myId).fold(maintenanceTask.encryptionKeys) { m, d ->
            m + (d to setOf(DelegationDto(emptyList(), myId, d, this.crypto.encryptAESKeyForDataOwner(myId, d, maintenanceTask.id, secret).first)))
        })
    }.let { p ->
        val key = this.crypto.decryptEncryptionKeys(myId, p.encryptionKeys)
            .firstOrNull()
            ?.keyFromHexString() 
            ?: throw IllegalArgumentException("No encryption key for user")
        
        val (sanitizedMaintenanceTask, marshalledData) = this.marshaller(p)
        sanitizedMaintenanceTask.applyIf({ marshalledData.isNotEmpty() }) {
            sanitizedMaintenanceTask.copy(encryptedSelf = Base64.getEncoder().encodeToString(
                CryptoUtils.encryptAES(
                    data = marshalledData,
                    key = key
                )
            ))
        }
    }
}

suspend fun CryptoConfig<MaintenanceTaskDto, io.icure.kraken.client.models.MaintenanceTaskDto>.decryptMaintenanceTask(myId: String, maintenanceTask: io.icure.kraken.client.models.MaintenanceTaskDto): MaintenanceTaskDto {
    val key = this.crypto.decryptEncryptionKeys(myId, maintenanceTask.encryptionKeys)
        .firstOrNull()
        ?.keyFromHexString()
        ?: throw IllegalArgumentException("No encryption key for user")

    return this.unmarshaller(maintenanceTask,
        maintenanceTask.encryptedSelf?.let { es ->
            CryptoUtils.decryptAES(data = Base64.getDecoder().decode(es), key = key)
        } ?: byteArrayOf()
    )
}

data class PropertyWrapper(val typedValue: TypedValueDtoObject)


// MAPPING
@Mapper
interface MaintenanceTaskMapper {
    fun map(maintenanceTask: MaintenanceTaskDto): io.icure.kraken.client.models.MaintenanceTaskDto
    fun map(maintenanceTask: io.icure.kraken.client.models.MaintenanceTaskDto): MaintenanceTaskDto
}

object MaintenanceTaskMapperFactory {
    val instance = Mappers.getMapper(MaintenanceTaskMapper::class.java)
}