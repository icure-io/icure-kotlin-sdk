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
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.*
import kotlin.io.path.ExperimentalPathApi
import kotlin.time.Duration.Companion.days

@ExperimentalPathApi
@ExperimentalUnsignedTypes
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
internal class HealthcarePartyApiKtTest {
    private val iCureBackendUrl = System.getenv("ICURE_BE_URL") ?: "https://kraken.icure.dev"

    private val parentAuthorization = "Basic " + Base64.getEncoder().encodeToString("${System.getenv("PARENT_HCP_USERNAME")}:${System.getenv("PARENT_HCP_PASSWORD")}".toByteArray(Charsets.UTF_8))
    private val parentPrivKey = System.getenv("PARENT_HCP_PRIV_KEY").toPrivateKey()

    private val userApi = UserApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val hcpartyApi = HealthcarePartyApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val patientApi = PatientApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val deviceApi = DeviceApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val maintenanceTaskApi = MaintenanceTaskApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)

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

        val newUser = createUserForHcp(newHcp, parent)

        //val keyPath = "src/test/resources/io/icure/kraken/client/extendedapis/keys/${newHcp.id}-icc-priv.2048.key"
        //Path.of(keyPath).absolute().createFile().appendText(kp.privateKeyAsString(), Charsets.UTF_8)

        Assertions.assertNotNull(newUser.login)
        Assertions.assertTrue(newHcp.aesExchangeKeys.containsKey(kp.publicKeyAsString()))
        Assertions.assertTrue(newHcp.aesExchangeKeys[kp.publicKeyAsString()]!!.containsKey(newHcp.id))
        Assertions.assertTrue(newHcp.aesExchangeKeys[kp.publicKeyAsString()]!![newHcp.id]!!.containsKey(kp.publicKeyAsString().takeLast(12)))
    }

    @FlowPreview
    @Test
    fun hcpLostItsKey_And_Receive_Access_Back_Success_Test() = runBlocking {
        // Before
        val parentUser = userApi.getCurrentUser()
        val parent = hcpartyApi.getCurrentHealthcareParty()
        val parentLocalCrypto = LocalCrypto(ExtendedTestUtils.dataOwnerWrapperFor(iCureBackendUrl, parentAuthorization), mapOf(
                parent.id to listOf(parentPrivKey to parent.publicKey!!.toPublicKey()),
            ),
            maintenanceTaskApi
        )

        // When creating new HCP
        val newHcpKp1 = CryptoUtils.generateKeyPairRSA()
        var newHcp = createHealthcareParty(parentUser, parentLocalCrypto, newHcpKp1)
        val newUser = createUserForHcp(newHcp, parent)

        delay(3000) // User not active yet when trying to create data afterwards

        //Then at first, only its own key is part of the aesExchangeKeys
        Assertions.assertTrue(newHcp.hcPartyKeys.isEmpty())
        Assertions.assertTrue(newHcp.aesExchangeKeys.isNotEmpty())
        Assertions.assertEquals(newHcp.aesExchangeKeys.keys.size, 1)

        Assertions.assertEquals(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![newHcp.id]!!.size, 1)
        Assertions.assertTrue(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![newHcp.id]!!.containsKey(newHcpKp1.publicKeyAsString().takeLast(12)))

        // Given
        val newUserHcpApi = HealthcarePartyApi(basePath = iCureBackendUrl, authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newUserPatientApi = PatientApi(basePath = iCureBackendUrl, authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newUserMaintenanceTaskApi = MaintenanceTaskApi(basePath = iCureBackendUrl, authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newHcpLocalCrypto1 = LocalCrypto(
            ExtendedTestUtils.dataOwnerWrapperFor(
                iCureBackendUrl,
                "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}"
            ), mapOf(
                newUser.dataOwnerId() to listOf(newHcpKp1.private as RSAPrivateKey to newHcpKp1.public as RSAPublicKey)
            ), newUserMaintenanceTaskApi
        )

        // When HCP creates data
        val patientCreatedByNewHcp = newUserPatientApi.createPatient(newUser, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), patientCryptoConfig(newHcpLocalCrypto1))

        // Then it created new aesExchangeKeys for its auto-delegations
        newHcp = newUserHcpApi.getCurrentHealthcareParty()
        Assertions.assertEquals(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![parent.id]!!.size, 2)
        Assertions.assertTrue(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![parent.id]!!.containsKey(newHcpKp1.publicKeyAsString().takeLast(12)))
        Assertions.assertTrue(newHcp.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![parent.id]!!.containsKey(parent.publicKey!!.takeLast(12)))

        // Given
        val newHcpKp2 = CryptoUtils.generateKeyPairRSA()
        val newHcpKp2DoResolver = ExtendedTestUtils.dataOwnerWrapperFor(
            iCureBackendUrl,
            "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}"
        )
        val newHcpLocalCrypto2 = LocalCrypto(
            newHcpKp2DoResolver, mapOf(
                newUser.dataOwnerId() to listOf(newHcpKp2.private as RSAPrivateKey to newHcpKp2.public as RSAPublicKey)
            ), newUserMaintenanceTaskApi
        )

        // When HCP lost his keyPair and decides to use a new one
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

        // When parent gets its maintenanceTasks to check if any task requires its action
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

        // When hcp tries to access patient he previously created
        val notDecryptedPatient = newUserPatientApi.getPatient(newUser, patientCreatedByNewHcp.id, patientCryptoConfig(newHcpLocalCrypto2))

        // Then He can't, because its key is not authorized for it
        assert(notDecryptedPatient.note == null)

        //TODO Add giveAccessTo in order to add delegation back with new key
    }

    @FlowPreview
    @Test
    fun hcpFoundBackItsKeyAfterReEncryptingInfoWithOtherKeys_Success_Test() = runBlocking {
        // Before
        val parentUser = userApi.getCurrentUser()
        val parent = hcpartyApi.getCurrentHealthcareParty()
        val parentLocalCrypto = LocalCrypto(ExtendedTestUtils.dataOwnerWrapperFor(iCureBackendUrl, parentAuthorization), mapOf(
                parent.id to listOf(parentPrivKey to parent.publicKey!!.toPublicKey()),
            ),
            maintenanceTaskApi
        )

        val newHcpKp1 = CryptoUtils.generateKeyPairRSA()
        var newHcp = createHealthcareParty(parentUser, parentLocalCrypto, newHcpKp1)
        val newUser = createUserForHcp(newHcp, parent)

        delay(4000) // User not active yet when trying to create data afterwards

        val newUserHcpApi = HealthcarePartyApi(basePath = iCureBackendUrl, authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newUserPatientApi = PatientApi(basePath = iCureBackendUrl, authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newUserMaintenanceTaskApi = MaintenanceTaskApi(basePath = iCureBackendUrl, authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newHcpLocalCrypto1 = LocalCrypto(
            ExtendedTestUtils.dataOwnerWrapperFor(
                iCureBackendUrl,
                "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}"
            ), mapOf(
                newUser.dataOwnerId() to listOf(newHcpKp1.private as RSAPrivateKey to newHcpKp1.public as RSAPublicKey)
            ), newUserMaintenanceTaskApi
        )

        // When
        val patientCreatedWithKey1 = newUserPatientApi.createPatient(newUser, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), patientCryptoConfig(newHcpLocalCrypto1))

        // Given
        val newHcpKp2 = CryptoUtils.generateKeyPairRSA()
        val newHcpLocalCrypto2 = LocalCrypto(
            ExtendedTestUtils.dataOwnerWrapperFor(
                iCureBackendUrl,
                "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}"
            ), mapOf(
                newUser.dataOwnerId() to listOf(newHcpKp2.private as RSAPrivateKey to newHcpKp2.public as RSAPublicKey)
            ), newUserMaintenanceTaskApi
        )

        newHcp = newUserHcpApi.getCurrentHealthcareParty()
        val hcpToUpdate = newHcp.addNewKeyPair(newUser, newHcpLocalCrypto2, newHcpKp2.public, newHcpKp2.private)
        newUserHcpApi.modifyHealthcareParty(hcpToUpdate)

        // When HCP creates data
        val patientCreatedWithKey2 = newUserPatientApi.createPatient(newUser, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), patientCryptoConfig(newHcpLocalCrypto2))

        // Then
        val foundPatient1ForKey2 = newUserPatientApi.getPatient(newUser, patientCreatedWithKey1.id, patientCryptoConfig(newHcpLocalCrypto2))
        assert(foundPatient1ForKey2.note == null)

        val foundPatient2ForKey1 = newUserPatientApi.getPatient(newUser, patientCreatedWithKey2.id, patientCryptoConfig(newHcpLocalCrypto1))
        assert(foundPatient2ForKey1.note == "To be encrypted")
    }

    private suspend fun createUserForHcp(
        newHcp: HealthcarePartyDto,
        parent: HealthcarePartyDto
    ) = userApi.createUser(
        UserDto(
            id = UUID.randomUUID().toString(),
            login = "jimmy-${System.currentTimeMillis()}",
            type = UserDto.Type.database,
            status = UserDto.Status.aCTIVE,
            name = "${newHcp.firstName} ${newHcp.lastName}",
            authenticationTokens = mapOf(
                "test" to AuthenticationTokenDto(
                    "test",
                    Instant.now().toEpochMilli(),
                    365.days.inWholeSeconds
                )
            ),
            healthcarePartyId = newHcp.id,
            autoDelegations = mapOf("all" to setOf(parent.id))
        )
    )

    private suspend fun createHealthcareParty(
        parentUser: UserDto,
        parentLocalCrypto: LocalCrypto,
        hcpKeyPair: KeyPair,
        firstName: String = "Jimmy",
        lastName: String = "Materazzi"
    ) = hcpartyApi.createHealthcareParty(
        HealthcarePartyDto(
            id = UUID.randomUUID().toString(),
            firstName = firstName,
            lastName = lastName
        )
            .initHcParty()
            .addNewKeyPair(parentUser, parentLocalCrypto, hcpKeyPair.public)
    )

    @FlowPreview
    @Test
    fun `old hcp giveAccess to newly created patient to hcp1`() = runBlocking {
        val parentUser = userApi.getCurrentUser()
        val parent = hcpartyApi.getCurrentHealthcareParty()
        val parentLocalCrypto = LocalCrypto(ExtendedTestUtils.dataOwnerWrapperFor(iCureBackendUrl, parentAuthorization), mapOf(
            parent.id to listOf(parentPrivKey to parent.publicKey!!.toPublicKey()),
        ),
            maintenanceTaskApi
        )

        val hcp1Kp = CryptoUtils.generateKeyPairRSA()

        val hcp1User = createUserForHcp(
            createHealthcareParty(parentUser, parentLocalCrypto, hcp1Kp, "Bender Bending", "Rodriguez"),
            parent
        )

        val hcp1Auth =
            "Basic ${Base64.getEncoder().encodeToString("${hcp1User.login}:test".toByteArray(Charsets.UTF_8))}"

        val hcp1PatientApi = PatientApi(basePath = iCureBackendUrl, authHeader = hcp1Auth)

        val ccPatient = {
            auth: String, user: UserDto, kp: KeyPair ->
            patientCryptoConfig(
                LocalCrypto(
                    ExtendedTestUtils.dataOwnerWrapperFor(
                        iCureBackendUrl,
                        auth
                    ), mapOf(
                        user.dataOwnerId() to listOf(kp.private as RSAPrivateKey to kp.public as RSAPublicKey)
                    )
                )
            )
        }

        val cc1 = ccPatient(hcp1Auth, hcp1User, hcp1Kp)
        val ccParent = patientCryptoConfig(ExtendedTestUtils.localCrypto(iCureBackendUrl, parentAuthorization, parentPrivKey, parentUser, parent.toDataOwner()))

        delay(4000)

        // When
        val p1 = try {
            patientApi.createPatient(
                parentUser,
                PatientDto(
                    id = UUID.randomUUID().toString(),
                    firstName = "Hermez",
                    lastName = "Conrad",
                    note = "Sweet manatee of Galilee!"
                ),
                ccParent
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertNotNull(p1, "Patient should not be null")

        val sharedP1 = patientApi.giveAccessTo(ccParent, parentUser, p1, hcp1User.dataOwnerId())
        val p2 = try { hcp1PatientApi.getPatient(hcp1User, p1.id, cc1)
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertEquals(sharedP1, p2)
    }

    @FlowPreview
    @Test
    fun `hcp1 giveAccess to newly created patient to hcp2`() = runBlocking {
        val parentLocalCrypto = LocalCrypto(DataOwnerResolver(hcpartyApi, patientApi, deviceApi), emptyMap(), maintenanceTaskApi)
        val parentUser = userApi.getCurrentUser()
        val parent = hcpartyApi.getCurrentHealthcareParty()

        val hcp1Kp = CryptoUtils.generateKeyPairRSA()
        val hcp2Kp = CryptoUtils.generateKeyPairRSA()

        val hcp1User = createUserForHcp(
            createHealthcareParty(parentUser, parentLocalCrypto, hcp1Kp, "Bender Bending", "Rodriguez"),
            parent
        )
        val hcp2User = createUserForHcp(
            createHealthcareParty(parentUser, parentLocalCrypto, hcp2Kp, "Philip J.", "Fry"),
            parent
        )

        val hcp1Auth =
            "Basic ${Base64.getEncoder().encodeToString("${hcp1User.login}:test".toByteArray(Charsets.UTF_8))}"
        val hcp2Auth =
            "Basic ${Base64.getEncoder().encodeToString("${hcp2User.login}:test".toByteArray(Charsets.UTF_8))}"

        val hcp1PatientApi = PatientApi(basePath = iCureBackendUrl, authHeader = hcp1Auth)
        val hcp2PatientApi = PatientApi(basePath = iCureBackendUrl, authHeader = hcp2Auth)

        val ccPatient = {
            auth: String, user: UserDto, kp: KeyPair ->
            patientCryptoConfig(
                LocalCrypto(
                    ExtendedTestUtils.dataOwnerWrapperFor(
                        iCureBackendUrl,
                        auth
                    ), mapOf(
                        user.dataOwnerId() to listOf(kp.private as RSAPrivateKey to kp.public as RSAPublicKey)
                    )
                )
            )
        }

        val cc1 = ccPatient(hcp1Auth, hcp1User, hcp1Kp)
        val cc2 = ccPatient(hcp2Auth, hcp2User, hcp2Kp)

        delay(4000)

        // When
        val p1 = try {
            hcp1PatientApi.createPatient(
                hcp1User,
                PatientDto(
                    id = UUID.randomUUID().toString(),
                    firstName = "Hermez",
                    lastName = "Conrad",
                    note = "Sweet manatee of Galilee!"
                ),
                cc1
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertNotNull(p1, "Patient should not be null")

        val sharedP1 = hcp1PatientApi.giveAccessTo(cc1, hcp1User, p1, hcp2User.dataOwnerId())
        val p2 = try {
            hcp2PatientApi.getPatient(hcp2User, p1.id, cc2)
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertEquals(sharedP1, p2)
    }
}
