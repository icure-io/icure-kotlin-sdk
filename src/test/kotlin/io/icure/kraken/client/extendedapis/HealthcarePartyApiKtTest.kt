package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.DeviceApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.MaintenanceTaskApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.maintenanceTaskCryptoConfig
import io.icure.kraken.client.crypto.patientCryptoConfig
import io.icure.kraken.client.crypto.privateKeyAsString
import io.icure.kraken.client.crypto.publicKeyAsString
import io.icure.kraken.client.crypto.toPrivateKey
import io.icure.kraken.client.crypto.toPublicKey
import io.icure.kraken.client.extendedapis.infrastructure.ExtendedTestUtils
import io.icure.kraken.client.models.AuthenticationTokenDto
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.PatientDto
import io.icure.kraken.client.models.filter.chain.FilterChain
import io.icure.kraken.client.models.filter.maintenancetask.MaintenanceTaskByHcPartyAndTypeFilter
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.nio.file.Path
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.*
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.absolute
import kotlin.io.path.appendText
import kotlin.io.path.createFile

@ExperimentalPathApi
@ExperimentalUnsignedTypes
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
internal class HealthcarePartyApiKtTest {
    private val userApi = UserApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val hcpartyApi = HealthcarePartyApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val patientApi = PatientApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val deviceApi = DeviceApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val maintenanceTaskApi = MaintenanceTaskApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

    @FlowPreview
    @Test
    fun createHcPartyTest() = runBlocking {
        val localCrypto = LocalCrypto(DataOwnerResolver(hcpartyApi, patientApi, deviceApi), emptyMap(), maintenanceTaskApi)
        val parentUser = userApi.getCurrentUser()
        val parent = hcpartyApi.getCurrentHealthcareParty()
        val kp = CryptoUtils.generateKeyPairRSA()

        val newHcp = hcpartyApi.createHealthcareParty(
            HealthcarePartyDto(
                id = UUID.randomUUID().toString(),
                firstName = "Jimmy",
                lastName = "Materazzi",
                parentId = parent.id
            ).initHcParty().addNewKeyPair(parentUser, localCrypto, kp.public))

        val newUser = userApi.createUser(UserDto(
            id = UUID.randomUUID().toString(),
            login = "jimmy-${System.currentTimeMillis()}",
            type = UserDto.Type.database,
            status = UserDto.Status.aCTIVE,
            name = "${newHcp.firstName} ${newHcp.lastName}",
            authenticationTokens = mapOf("test" to AuthenticationTokenDto("test", Instant.now().toEpochMilli(), 24 * 3600 * 365)),
            healthcarePartyId = newHcp.id,
            autoDelegations = mapOf("all" to setOf(parent.id))
        ))

        val keyPath = "src/test/resources/io/icure/kraken/client/extendedapis/keys/${newHcp.id}-icc-priv.2048.key"
        Path.of(keyPath).absolute().createFile().appendText(kp.privateKeyAsString(), Charsets.UTF_8)

        Assertions.assertNotNull(newUser.login)
        Assertions.assertTrue(newHcp.aesExchangeKeys.containsKey(kp.publicKeyAsString()))
        Assertions.assertTrue(newHcp.aesExchangeKeys[kp.publicKeyAsString()]!!.containsKey(newHcp.id))
        Assertions.assertTrue(newHcp.aesExchangeKeys[kp.publicKeyAsString()]!![newHcp.id]!!.containsKey(kp.publicKeyAsString().takeLast(12)))
    }

    @FlowPreview
    @Test
    fun hcpLostItsKey_Success_Test() = runBlocking {
        // Before
        val parentUser = userApi.getCurrentUser()
        val parent = hcpartyApi.getCurrentHealthcareParty()
        val parentKeyPath = "keys/${parent.id}-icc-priv.2048.key"
        val parentKeyFile = HealthcarePartyApiKtTest::class.java.getResource(parentKeyPath)!!
        val parentLocalCrypto = LocalCrypto(
            ExtendedTestUtils.dataOwnerWrapperFor(
                "https://kraken.icure.dev",
                "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM="
            ), mapOf(
                parent.id to listOf(parentKeyFile.readText(Charsets.UTF_8).toPrivateKey() to parent.publicKey!!.toPublicKey()),
            ),
            maintenanceTaskApi
        )

        // When
        val newHcpKp1 = CryptoUtils.generateKeyPairRSA()
        var newHcp = hcpartyApi.createHealthcareParty(
            HealthcarePartyDto(
                id = UUID.randomUUID().toString(),
                firstName = "Jimmy",
                lastName = "Materazzi"
            )
                .initHcParty()
                .addNewKeyPair(parentUser, parentLocalCrypto, newHcpKp1.public)
        )
        val newUser = userApi.createUser(
            UserDto(
                id = UUID.randomUUID().toString(),
                login = "jimmy-${System.currentTimeMillis()}",
                type = UserDto.Type.database,
                status = UserDto.Status.aCTIVE,
                name = "${newHcp.firstName} ${newHcp.lastName}",
                authenticationTokens = mapOf("test" to AuthenticationTokenDto("test", Instant.now().toEpochMilli(), 24 * 3600 * 365)),
                healthcarePartyId = newHcp.id,
                autoDelegations = mapOf("all" to setOf(parent.id))
            )
        )

        //Then
        Assertions.assertTrue(newHcp.hcPartyKeys.isEmpty())
        Assertions.assertTrue(newHcp.aesExchangeKeys.isNotEmpty())
        Assertions.assertEquals(newHcp.aesExchangeKeys.keys.size, 1)

        Assertions.assertEquals(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![newHcp.id]!!.size, 1)
        Assertions.assertTrue(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![newHcp.id]!!.containsKey(newHcpKp1.publicKeyAsString().takeLast(12)))

        // Given
        val newUserHcpApi = HealthcarePartyApi(basePath = "https://kraken.icure.dev", authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newUserPatientApi = PatientApi(basePath = "https://kraken.icure.dev", authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newUserMaintenanceTaskApi = MaintenanceTaskApi(basePath = "https://kraken.icure.dev", authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newHcpLocalCrypto1 = LocalCrypto(
            ExtendedTestUtils.dataOwnerWrapperFor(
                "https://kraken.icure.dev",
                "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}"
            ), mapOf(
                newUser.dataOwnerId() to listOf(newHcpKp1.private as RSAPrivateKey to newHcpKp1.public as RSAPublicKey)
            ), newUserMaintenanceTaskApi
        )

        // When
        newUserPatientApi.createPatient(newUser, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), patientCryptoConfig(newHcpLocalCrypto1))

        // Then
        newHcp = newUserHcpApi.getCurrentHealthcareParty()
        Assertions.assertEquals(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![parent.id]!!.size, 2)
        Assertions.assertTrue(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![parent.id]!!.containsKey(newHcpKp1.publicKeyAsString().takeLast(12)))
        Assertions.assertTrue(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![parent.id]!!.containsKey(parent.publicKey!!.takeLast(12)))

        // Given
        val newHcpKp2 = CryptoUtils.generateKeyPairRSA()
        val newHcpKp2DoResolver = ExtendedTestUtils.dataOwnerWrapperFor(
            "https://kraken.icure.dev",
            "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}"
        )
        val newHcpLocalCrypto2 = LocalCrypto(
            newHcpKp2DoResolver, mapOf(
                newUser.dataOwnerId() to listOf(newHcpKp2.private as RSAPrivateKey to newHcpKp2.public as RSAPublicKey)
            ), newUserMaintenanceTaskApi
        )

        // When
        newHcp = newUserHcpApi.getCurrentHealthcareParty()
        val hcpToUpdate = newHcp.addNewKeyPair(newUser, newHcpLocalCrypto2, newHcpKp2.public, newHcpKp2.private)
        val newHcpUpdated = newUserHcpApi.modifyHealthcareParty(hcpToUpdate)

        // Then
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys.isNotEmpty())
        Assertions.assertEquals(newHcpUpdated.aesExchangeKeys.keys.size, 2)

        Assertions.assertEquals(newHcpUpdated.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![newHcpUpdated.id]!!.size, 1)
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![newHcpUpdated.id]!!.containsKey(newHcpKp1.publicKeyAsString().takeLast(12)))

        Assertions.assertEquals(newHcpUpdated.aesExchangeKeys[newHcpKp2.publicKeyAsString()]!![newHcpUpdated.id]!!.size, 2)
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys[newHcpKp2.publicKeyAsString()]!![newHcpUpdated.id]!!.containsKey(newHcpKp1.publicKeyAsString().takeLast(12)))
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys[newHcpKp2.publicKeyAsString()]!![newHcpUpdated.id]!!.containsKey(newHcpKp2.publicKeyAsString().takeLast(12)))

        Assertions.assertTrue(newHcpUpdated.transferKeys[newHcpKp1.publicKeyAsString()]!!.containsKey(newHcpKp2.publicKeyAsString()))

        // Given
        newHcpKp2DoResolver.clearCacheFor(newHcpUpdated.id)

        // When
        val parentTasksToDo = maintenanceTaskApi.filterMaintenanceTasksBy(parentUser,
            FilterChain(MaintenanceTaskByHcPartyAndTypeFilter(
                parent.id,
                "updateAesExchangeKey"
            )),
            null, null,
            maintenanceTaskCryptoConfig(parentLocalCrypto, parentUser)).rows

        // Then
        assert(parentTasksToDo.any { task -> task.properties.any { it.typedValue?.stringValue == newHcp.id } })
        assert(parentTasksToDo.any { task -> task.properties.any { it.typedValue?.stringValue == newHcpKp1.publicKeyAsString() } })
    }
}
