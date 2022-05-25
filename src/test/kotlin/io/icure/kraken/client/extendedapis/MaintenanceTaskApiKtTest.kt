package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.MaintenanceTaskApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.maintenanceTaskCryptoConfig
import io.icure.kraken.client.crypto.toPrivateKey
import io.icure.kraken.client.crypto.toPublicKey
import io.icure.kraken.client.extendedapis.infrastructure.ExtendedTestUtils
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.IdentifierDto
import io.icure.kraken.client.models.PropertyStubDto
import io.icure.kraken.client.models.PropertyTypeStubDto
import io.icure.kraken.client.models.TypedValueDtoObject
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.MaintenanceTaskDto
import io.icure.kraken.client.models.filter.chain.FilterChain
import io.icure.kraken.client.models.filter.maintenancetask.MaintenanceTaskAfterDateFilter
import io.icure.kraken.client.models.filter.maintenancetask.MaintenanceTaskByHcPartyAndIdentifiersFilter
import io.icure.kraken.client.models.filter.maintenancetask.MaintenanceTaskByHcPartyAndTypeFilter
import io.icure.kraken.client.models.filter.maintenancetask.MaintenanceTaskByIdsFilter
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.UUID

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
@FlowPreview
internal class MaintenanceTaskApiKtTest {
    private val hcp1UserApi = UserApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val hcp1HcPartyApi = HealthcarePartyApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val hcp1MaintenanceTaskApi = MaintenanceTaskApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

    private val hcp2UserApi = UserApi(basePath = "https://kraken.icure.dev", authHeader = "Basic dGVzdC0yLXR6LWRldi10ZWFtLzE0NGJhYTc3LTQ1YTMtNDgxZi1iNTcxLWRlYjM2YTIyOWI4ZjozOTI3MjRjOC0zYWFmLTQzMmYtYWU3My0zNDQzMTk4ZDQyMTI=")
    private val hcp2HcPartyApi = HealthcarePartyApi(basePath = "https://kraken.icure.dev", authHeader = "Basic dGVzdC0yLXR6LWRldi10ZWFtLzE0NGJhYTc3LTQ1YTMtNDgxZi1iNTcxLWRlYjM2YTIyOWI4ZjozOTI3MjRjOC0zYWFmLTQzMmYtYWU3My0zNDQzMTk4ZDQyMTI=")
    private val hcp2MaintenanceTaskApi = MaintenanceTaskApi(basePath = "https://kraken.icure.dev", authHeader = "Basic dGVzdC0yLXR6LWRldi10ZWFtLzE0NGJhYTc3LTQ1YTMtNDgxZi1iNTcxLWRlYjM2YTIyOWI4ZjozOTI3MjRjOC0zYWFmLTQzMmYtYWU3My0zNDQzMTk4ZDQyMTI=")

    @Test
    fun test_CreateMaintenanceTask_Success() = runBlocking {
        // Given
        val hcp1User = hcp1UserApi.getCurrentUser()
        val hcp1 = hcp1HcPartyApi.getCurrentHealthcareParty()
        val hcp1cc = cryptoConfigFor(hcp1User, hcp1, "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

        val hcp2User = hcp2UserApi.getCurrentUser()
        val hcp2 = hcp2HcPartyApi.getCurrentHealthcareParty()
        val hcp2cc = cryptoConfigFor(hcp2User, hcp2, "Basic dGVzdC0yLXR6LWRldi10ZWFtLzE0NGJhYTc3LTQ1YTMtNDgxZi1iNTcxLWRlYjM2YTIyOWI4ZjozOTI3MjRjOC0zYWFmLTQzMmYtYWU3My0zNDQzMTk4ZDQyMTI=", mapOf(rsaKeyPairFor(hcp1)))

        val taskToCreate = maintenanceTaskDto(delegatedTo = hcp2)

        // When
        val createdTask = hcp1MaintenanceTaskApi.createMaintenanceTask(hcp1User, taskToCreate, hcp2.id, hcp1cc)

        // Then
        assert(createdTask.id == taskToCreate.id)
        assert(createdTask.delegations.containsKey(hcp1.id))
        assert(createdTask.delegations.containsKey(hcp2.id))
        assert(createdTask.encryptionKeys.containsKey(hcp1.id))
        assert(createdTask.encryptionKeys.containsKey(hcp2.id))

        // When
        val foundTask = hcp2MaintenanceTaskApi.getMaintenanceTask(hcp2User, createdTask.id, hcp2cc)

        // Then
        assert(foundTask.id == createdTask.id)
        assert(foundTask.properties.any { it.typedValue?.stringValue == hcp2.id })
        assert(foundTask.properties.any { it.typedValue?.stringValue == hcp2.publicKey })
    }

    @Test
    fun test_ModifyMaintenanceTask_Success() = runBlocking {
        // Given
        val hcp1User = hcp1UserApi.getCurrentUser()
        val hcp1 = hcp1HcPartyApi.getCurrentHealthcareParty()
        val hcp1cc = cryptoConfigFor(hcp1User, hcp1, "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

        val createdTask = hcp1MaintenanceTaskApi.createMaintenanceTask(hcp1User, maintenanceTaskDto(delegatedTo = hcp1), config = hcp1cc)

        // When
        val identifierToAdd = IdentifierDto(id = "SYSTEM-TEST|VALUE-TEST", system = "SYSTEM-TEST", value = "VALUE-TEST",)
        val modifiedTask = hcp1MaintenanceTaskApi.modifyMaintenanceTask(hcp1User, createdTask.copy(
            identifier = listOf(identifierToAdd), status = MaintenanceTaskDto.Status.ongoing
        ), hcp1cc)

        // Then
        assert(modifiedTask.id == createdTask.id)
        assert(modifiedTask.identifier.contains(identifierToAdd))
        assert(modifiedTask.status == MaintenanceTaskDto.Status.ongoing)
    }

    @Test
    fun test_DeleteMaintenanceTask_Success() = runBlocking {
        // Given
        val hcp1User = hcp1UserApi.getCurrentUser()
        val hcp1 = hcp1HcPartyApi.getCurrentHealthcareParty()
        val hcp1cc = cryptoConfigFor(hcp1User, hcp1, "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

        val createdTask = hcp1MaintenanceTaskApi.createMaintenanceTask(hcp1User, maintenanceTaskDto(delegatedTo = hcp1), config = hcp1cc)

        // When
        val deletedTasks = hcp1MaintenanceTaskApi.deleteMaintenanceTask(createdTask.id)

        // Then
        assert(deletedTasks.size == 1)
        assert(deletedTasks.first().id == createdTask.id)

        // When
        val foundMaintenanceTaskDto = hcp2MaintenanceTaskApi.getMaintenanceTask(hcp1User, createdTask.id, hcp1cc)

        // Then
        assert(foundMaintenanceTaskDto.deletionDate != null)
    }

    @Test
    fun test_FilterMaintenanceTaskByIds_Success() = runBlocking {
        // Given
        val hcp1User = hcp1UserApi.getCurrentUser()
        val hcp1 = hcp1HcPartyApi.getCurrentHealthcareParty()
        val hcp1cc = cryptoConfigFor(hcp1User, hcp1, "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

        val createdTask = hcp1MaintenanceTaskApi.createMaintenanceTask(hcp1User, maintenanceTaskDto(delegatedTo = hcp1), config = hcp1cc)

        // When
        val foundTasks = hcp1MaintenanceTaskApi.filterMaintenanceTasksBy(
            hcp1User,
            FilterChain(MaintenanceTaskByIdsFilter(ids = setOf(createdTask.id))),
            config = hcp1cc).rows

        // Then
        assert(foundTasks.first() == createdTask)
    }

    @Test
    fun test_FilterMaintenanceTaskByHcpAndIdentifier_Success() = runBlocking {
        // Given
        val hcp1User = hcp1UserApi.getCurrentUser()
        val hcp1 = hcp1HcPartyApi.getCurrentHealthcareParty()
        val hcp1cc = cryptoConfigFor(hcp1User, hcp1, "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

        val identifierUuid = UUID.randomUUID().toString()
        val taskIdentifier = IdentifierDto(id = "SYSTEM-TEST|$identifierUuid", system = "SYSTEM-TEST", value = identifierUuid)
        val createdTask = hcp1MaintenanceTaskApi.createMaintenanceTask(hcp1User, maintenanceTaskDto(delegatedTo = hcp1)
            .copy(identifier = listOf(taskIdentifier)), config = hcp1cc)

        // When
        val foundTasks = hcp1MaintenanceTaskApi.filterMaintenanceTasksBy(
            hcp1User,
            FilterChain(MaintenanceTaskByHcPartyAndIdentifiersFilter(healthcarePartyId = hcp1.id, identifiers = listOf(taskIdentifier))),
            config = hcp1cc).rows

        // Then
        assert(foundTasks.first() == createdTask)
    }

    @Test
    fun test_FilterMaintenanceTaskAfterDate_Success() = runBlocking {
        // Given
        val hcp1User = hcp1UserApi.getCurrentUser()
        val hcp1 = hcp1HcPartyApi.getCurrentHealthcareParty()
        val hcp1cc = cryptoConfigFor(hcp1User, hcp1, "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

        val createdTask = hcp1MaintenanceTaskApi.createMaintenanceTask(hcp1User, maintenanceTaskDto(delegatedTo = hcp1)
            .copy(created = Instant.now().plusSeconds(60 * 5).toEpochMilli()), config = hcp1cc)

        // When
        val foundTasks = hcp1MaintenanceTaskApi.filterMaintenanceTasksBy(
            hcp1User,
            FilterChain(MaintenanceTaskAfterDateFilter(date = Instant.now().plusSeconds(60 * 4).toEpochMilli())),
            config = hcp1cc).rows

        // Then
        assert(foundTasks.first() == createdTask )
    }

    @Test
    fun test_FilterMaintenanceTaskByType_Success() = runBlocking {
            // Given
            val hcp1User = hcp1UserApi.getCurrentUser()
            val hcp1 = hcp1HcPartyApi.getCurrentHealthcareParty()
            val hcp1cc = cryptoConfigFor(hcp1User, hcp1, "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

            val taskTypeUuid = UUID.randomUUID().toString()
            val createdTask = hcp1MaintenanceTaskApi.createMaintenanceTask(hcp1User, maintenanceTaskDto(delegatedTo = hcp1)
                .copy(taskType = taskTypeUuid), config = hcp1cc)

            // When
            val foundTasks = hcp1MaintenanceTaskApi.filterMaintenanceTasksBy(
                hcp1User,
                FilterChain(MaintenanceTaskByHcPartyAndTypeFilter(type = taskTypeUuid, healthcarePartyId = hcp1.id)),
                config = hcp1cc).rows

            // Then
            assert(foundTasks.first() == createdTask)
        }

    private fun cryptoConfigFor(user: UserDto,
                                hcp: HealthcarePartyDto,
                                authHeader: String,
                                additionalRsaKeyPairs: Map<String, Pair<RSAPrivateKey, RSAPublicKey>> = emptyMap()) : CryptoConfig<MaintenanceTaskDto, io.icure.kraken.client.models.MaintenanceTaskDto> {
        return maintenanceTaskCryptoConfig(
            LocalCrypto(
                ExtendedTestUtils.dataOwnerWrapperFor(
                    "https://kraken.icure.dev",
                    authHeader
                ), mapOf(rsaKeyPairFor(hcp)) + additionalRsaKeyPairs
            ), user
        )
    }

    private fun rsaKeyPairFor(hcp: HealthcarePartyDto): Pair<String, Pair<RSAPrivateKey, RSAPublicKey>> {
        val hcp2KeyPath = "keys/${hcp.id}-icc-priv.2048.key"
        val hcp2KeyFile = MaintenanceTaskApiKtTest::class.java.getResource(hcp2KeyPath)!!
        return hcp.id to (hcp2KeyFile.readText(Charsets.UTF_8).toPrivateKey() to hcp.publicKey!!.toPublicKey())
    }


    private fun maintenanceTaskDto(delegatedTo: HealthcarePartyDto) = MaintenanceTaskDto(
        id = UUID.randomUUID().toString(),
        taskType = "sharing",
        status = MaintenanceTaskDto.Status.pending,
        properties = listOf(
            PropertyStubDto(
                id = "dataOwnerConcernedId",
                type = PropertyTypeStubDto(type = PropertyTypeStubDto.Type.sTRING),
                typedValue = TypedValueDtoObject(
                    type = TypedValueDtoObject.Type.sTRING,
                    stringValue = delegatedTo.id
                )
            ),
            PropertyStubDto(
                id = "dataOwnerConcernedPubKey",
                type = PropertyTypeStubDto(type = PropertyTypeStubDto.Type.sTRING),
                typedValue = TypedValueDtoObject(
                    type = TypedValueDtoObject.Type.sTRING,
                    stringValue = delegatedTo.publicKey
                )
            )
        )
    )

}