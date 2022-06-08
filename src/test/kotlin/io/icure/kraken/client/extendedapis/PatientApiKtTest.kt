package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.DeviceApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.MaintenanceTaskApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.patientCryptoConfig
import io.icure.kraken.client.crypto.publicKeyAsString
import io.icure.kraken.client.crypto.toPrivateKey
import io.icure.kraken.client.crypto.toPublicKey
import io.icure.kraken.client.extendedapis.infrastructure.ExtendedTestUtils
import io.icure.kraken.client.extendedapis.mapper.PatientMapperFactory
import io.icure.kraken.client.infrastructure.ApiClient
import io.icure.kraken.client.models.AuthenticationTokenDto
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.util.*

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
internal class PatientApiKtTest {
    private val userApi = UserApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val hcpartyApi = HealthcarePartyApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val patientApi = PatientApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val maintenanceTaskApi = MaintenanceTaskApi(basePath = "https://kraken.icure.dev", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

    private val child1UserApi = UserApi(basePath = "https://kraken.icure.dev", authHeader = "Basic dGVzdC0yLXR6LWRldi10ZWFtLzE0NGJhYTc3LTQ1YTMtNDgxZi1iNTcxLWRlYjM2YTIyOWI4ZjozOTI3MjRjOC0zYWFmLTQzMmYtYWU3My0zNDQzMTk4ZDQyMTI=")
    private val child1HealthcarePartyApi = HealthcarePartyApi(basePath = "https://kraken.icure.dev", authHeader = "Basic dGVzdC0yLXR6LWRldi10ZWFtLzE0NGJhYTc3LTQ1YTMtNDgxZi1iNTcxLWRlYjM2YTIyOWI4ZjozOTI3MjRjOC0zYWFmLTQzMmYtYWU3My0zNDQzMTk4ZDQyMTI=")
    private val child1DeviceApi = DeviceApi(basePath = "https://kraken.icure.dev", authHeader = "Basic dGVzdC0yLXR6LWRldi10ZWFtLzE0NGJhYTc3LTQ1YTMtNDgxZi1iNTcxLWRlYjM2YTIyOWI4ZjozOTI3MjRjOC0zYWFmLTQzMmYtYWU3My0zNDQzMTk4ZDQyMTI=")
    private val child1PatientApi = PatientApi(basePath = "https://kraken.icure.dev", authHeader = "Basic dGVzdC0yLXR6LWRldi10ZWFtLzE0NGJhYTc3LTQ1YTMtNDgxZi1iNTcxLWRlYjM2YTIyOWI4ZjozOTI3MjRjOC0zYWFmLTQzMmYtYWU3My0zNDQzMTk4ZDQyMTI=")

    private val child2UserApi = UserApi(basePath = "https://kraken.icure.dev", authHeader = "Basic MTkxYWUwZmUtN2QwZS00YTI2LTljZDMtY2RjMDk3NjNiNGMwQG1haWxrZXB0LmNvbTo2YzgyNTcyYS04ZWJhLTQ5ZWYtYjZjNC03NDQ2NDg5OTA3ODM=")
    private val child2HealthcarePartyApi = HealthcarePartyApi(basePath = "https://kraken.icure.dev", authHeader = "Basic MTkxYWUwZmUtN2QwZS00YTI2LTljZDMtY2RjMDk3NjNiNGMwQG1haWxrZXB0LmNvbTo2YzgyNTcyYS04ZWJhLTQ5ZWYtYjZjNC03NDQ2NDg5OTA3ODM=")
    private val child2DeviceApi = DeviceApi(basePath = "https://kraken.icure.dev", authHeader = "Basic MTkxYWUwZmUtN2QwZS00YTI2LTljZDMtY2RjMDk3NjNiNGMwQG1haWxrZXB0LmNvbTo2YzgyNTcyYS04ZWJhLTQ5ZWYtYjZjNC03NDQ2NDg5OTA3ODM=")
    private val child2PatientApi = PatientApi(basePath = "https://kraken.icure.dev", authHeader = "Basic MTkxYWUwZmUtN2QwZS00YTI2LTljZDMtY2RjMDk3NjNiNGMwQG1haWxrZXB0LmNvbTo2YzgyNTcyYS04ZWJhLTQ5ZWYtYjZjNC03NDQ2NDg5OTA3ODM=")


    @org.junit.jupiter.api.Test
    @FlowPreview
    fun createPatientWithCustomCryptoConfig() = runBlocking {
        // Before
        val user = userApi.getCurrentUser()
        val hcp = hcpartyApi.getCurrentHealthcareParty()
        val keyPath = "keys/${hcp.id}-icc-priv.2048.key"
        val keyFile = PatientApiKtTest::class.java.getResource(keyPath)!!
        val cc = customPatientCryptoConfig(ExtendedTestUtils.localCrypto("https://kraken.icure.dev",
            "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=", keyFile, user, hcp.toDataOwner()))

        // When
        val p1 = try { patientApi.createPatient(user, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), cc) } catch(e:Exception) { throw IllegalStateException(e) }

        // Then
        Assertions.assertNotNull(p1, "Patient should not be null")
        Assertions.assertEquals(p1.lastName, "Doe", "Patient name should not be null")
        Assertions.assertEquals(p1.firstName, "John", "Patient firstName should not be null")

        val encryptedP1 = patientApi.getPatient(p1.id)
        Assertions.assertNull(encryptedP1.lastName, "Patient lastName should be null in db")
        Assertions.assertNull(encryptedP1.firstName, "Patient firstName should be null in db")
        Assertions.assertNotNull(encryptedP1.encryptionKeys, "Patient encryptionKeys should be not null in db")
        Assertions.assertNotNull(encryptedP1.encryptedSelf, "Patient encryptedSelf should be not null in db")

        val p2 = try { patientApi.getPatient(user, p1.id, cc) } catch(e:Exception) { throw IllegalStateException(e) }
        Assertions.assertEquals(p2.note, "To be encrypted")
        Assertions.assertEquals(p2.firstName, "John")
        Assertions.assertEquals(p2.lastName, "Doe")
    }
    @FlowPreview
    @org.junit.jupiter.api.Test
    fun createPatientWithDefaultCryptoConfig() = runBlocking {
        // Before
        val user = userApi.getCurrentUser()
        val hcp = hcpartyApi.getCurrentHealthcareParty()

        val keyPath = "keys/${hcp.id}-icc-priv.2048.key"
        val keyFile = PatientApiKtTest::class.java.getResource(keyPath)!!
        val cc = patientCryptoConfig(ExtendedTestUtils.localCrypto("https://kraken.icure.dev",
            "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=", keyFile, user, hcp.toDataOwner()))

        // When
        val p1 = try { patientApi.createPatient(user, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), cc) } catch(e:Exception) { throw IllegalStateException(e) }

        // Then
        Assertions.assertNotNull(p1, "Patient should not be null")
        Assertions.assertEquals(p1.note, "To be encrypted", "Patient note should not be null")
        Assertions.assertNull(patientApi.getPatient(p1.id).note, "Patient note should be null in db")

        val p2 = try { patientApi.getPatient(user, p1.id, cc) } catch(e:Exception) { throw IllegalStateException(e) }
        Assertions.assertEquals(p2.note, "To be encrypted")
        Assertions.assertEquals(p2.firstName, "John")
        Assertions.assertEquals(p2.lastName, "Doe")
    }


    @FlowPreview
    @org.junit.jupiter.api.Test
    fun createPatientWithDefaultCryptoConfigHcpWithParent() = runBlocking {
        val parent = userApi.getCurrentUser()
        val parentHcp = hcpartyApi.getCurrentHealthcareParty()
        val keyPath = "keys/${parent.healthcarePartyId}-icc-priv.2048.key"
        val keyFile = PatientApiKtTest::class.java.getResource(keyPath)!!

        // Before
        val user1 = child1UserApi.getCurrentUser()
        val hcp1 = child1HealthcarePartyApi.getCurrentHealthcareParty()

        val user2 = child2UserApi.getCurrentUser()
        val hcp2 = child2HealthcarePartyApi.getCurrentHealthcareParty()

        Assertions.assertNotNull(hcp1.parentId, "Hcp must have a parent for this test")
        Assertions.assertNotNull(hcp2.parentId, "Hcp must have a parent for this test")

        val keyPath1 = "keys/${hcp1.id}-icc-priv.2048.key"
        val keyFile1 = PatientApiKtTest::class.java.getResource(keyPath1)!!
        val cc1 = patientCryptoConfig(LocalCrypto(
            DataOwnerResolver(child1HealthcarePartyApi, child1PatientApi, child1DeviceApi), mapOf(
                parent.healthcarePartyId!! to listOf(keyFile.readText(Charsets.UTF_8).toPrivateKey() to parentHcp.publicKey!!.toPublicKey()),
                user1.healthcarePartyId!! to listOf(keyFile1.readText(Charsets.UTF_8).toPrivateKey() to hcp1.publicKey!!.toPublicKey())
            )
        ))

        val keyPath2 = "keys/${hcp2.id}-icc-priv.2048.key"
        val keyFile2 = PatientApiKtTest::class.java.getResource(keyPath2)!!
        val cc2 = patientCryptoConfig(LocalCrypto(
            DataOwnerResolver(child2HealthcarePartyApi, child2PatientApi, child2DeviceApi), mapOf(
                parent.healthcarePartyId!! to listOf(keyFile.readText(Charsets.UTF_8).toPrivateKey() to parentHcp.publicKey!!.toPublicKey()),
                user2.healthcarePartyId!! to listOf(keyFile2.readText(Charsets.UTF_8).toPrivateKey() to hcp2.publicKey!!.toPublicKey())
            )
        ))

        // When
        val p1 = try { child1PatientApi.createPatient(user1, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), cc1) } catch(e:Exception) { throw IllegalStateException(e) }
        val p2 = try { child2PatientApi.getPatient(user2, p1.id, cc2) } catch(e:Exception) { throw IllegalStateException(e) }

        // Then
        Assertions.assertNotNull(p1, "Patient should not be null")
        Assertions.assertEquals(p1.note, p2.note)
    }

    @ExperimentalUnsignedTypes
    @FlowPreview
    @org.junit.jupiter.api.Test
    fun createPatientWithNewHcpHavingMultipleKeys() = runBlocking {
        // Before
        val parentUser = userApi.getCurrentUser()
        val parent = hcpartyApi.getCurrentHealthcareParty()
        val parentKeyPath = "keys/${parent.id}-icc-priv.2048.key"
        val parentKeyFile = PatientApiKtTest::class.java.getResource(parentKeyPath)!!
        val parentLocalCrypto = LocalCrypto(
            ExtendedTestUtils.dataOwnerWrapperFor(
                "https://kraken.icure.dev",
                "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM="
            ), mapOf(
                parent.id to listOf(parentKeyFile.readText(Charsets.UTF_8).toPrivateKey() to parent.publicKey!!.toPublicKey()),
            ),
            maintenanceTaskApi
        )

        val newHcpKp1 = CryptoUtils.generateKeyPairRSA()
        val newHcpKp2 = CryptoUtils.generateKeyPairRSA()
        val newHcp = hcpartyApi.createHealthcareParty(
            HealthcarePartyDto(
                id = UUID.randomUUID().toString(),
                firstName = "Jimmy",
                lastName = "Materazzi",
                parentId = parent.id
            )
                .initHcParty()
                .addNewKeyPair(parentUser, parentLocalCrypto, newHcpKp1.public)
                .addNewKeyPair(parentUser, parentLocalCrypto, newHcpKp2.public, newHcpKp2.private)
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

        val newUserPatientApi = PatientApi(basePath = "https://kraken.icure.dev", authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val newUserHcpApi = HealthcarePartyApi(basePath = "https://kraken.icure.dev", authHeader = "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}")
        val cc1 = patientCryptoConfig(LocalCrypto(
            ExtendedTestUtils.dataOwnerWrapperFor(
                "https://kraken.icure.dev",
                "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}"
            ), mapOf(
                parent.id to listOf(parentKeyFile.readText(Charsets.UTF_8).toPrivateKey() to parent.publicKey!!.toPublicKey()),
                newUser.dataOwnerId() to listOf(newHcpKp1.private as RSAPrivateKey to newHcpKp1.public as RSAPublicKey)
            )
        ))
        val cc2 = patientCryptoConfig(LocalCrypto(
            ExtendedTestUtils.dataOwnerWrapperFor(
                "https://kraken.icure.dev",
                "Basic ${Base64.getEncoder().encodeToString("${newUser.login}:test".toByteArray(Charsets.UTF_8))}"
            ), mapOf(
                parent.id to listOf(parentKeyFile.readText(Charsets.UTF_8).toPrivateKey() to parent.publicKey!!.toPublicKey()),
                newUser.dataOwnerId() to listOf(newHcpKp2.private as RSAPrivateKey to newHcpKp2.public as RSAPublicKey)
            )
        ))

        // When
        val p1 = try { newUserPatientApi.createPatient(newUser, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), cc1) } catch(e:Exception) { throw IllegalStateException(e) }

        // Then
        Assertions.assertNotNull(p1, "Patient should not be null")
        Assertions.assertEquals(p1.note, "To be encrypted", "Patient note should not be null")
        Assertions.assertNull(newUserPatientApi.getPatient(p1.id).note, "Patient note should be null in db")

        val p2 = try { newUserPatientApi.getPatient(newUser, p1.id, cc2) } catch(e:Exception) { throw IllegalStateException(e) }
        Assertions.assertEquals(p2.note, "To be encrypted")
        Assertions.assertEquals(p2.firstName, "John")
        Assertions.assertEquals(p2.lastName, "Doe")

        val newHcpUpdated = newUserHcpApi.getCurrentHealthcareParty()
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys.isNotEmpty())
        Assertions.assertEquals(newHcpUpdated.aesExchangeKeys.keys.size, 2)

        Assertions.assertEquals(newHcpUpdated.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![newHcpUpdated.id]!!.size, 1)
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![newHcpUpdated.id]!!.containsKey(newHcpKp1.publicKeyAsString().takeLast(12)))

        Assertions.assertEquals(newHcpUpdated.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![parent.id]!!.size, 2)
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![parent.id]!!.containsKey(newHcpKp1.publicKeyAsString().takeLast(12)))
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys[newHcpKp1.publicKeyAsString()]!![parent.id]!!.containsKey(parent.publicKey!!.takeLast(12)))

        Assertions.assertEquals(newHcpUpdated.aesExchangeKeys[newHcpKp2.publicKeyAsString()]!![newHcpUpdated.id]!!.size, 2)
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys[newHcpKp2.publicKeyAsString()]!![newHcpUpdated.id]!!.containsKey(newHcpKp1.publicKeyAsString().takeLast(12)))
        Assertions.assertTrue(newHcpUpdated.aesExchangeKeys[newHcpKp2.publicKeyAsString()]!![newHcpUpdated.id]!!.containsKey(newHcpKp2.publicKeyAsString().takeLast(12)))

        Assertions.assertTrue(newHcpUpdated.hcPartyKeys.isEmpty())
    }

    private fun customPatientCryptoConfig(crypto: LocalCrypto) =
        CryptoConfig<PatientDto, io.icure.kraken.client.models.PatientDto>(
            crypto = crypto,
            marshaller = { p -> PatientMapperFactory.instance.map(p)
                .copy(
                    lastName = null,
                    firstName = null
                ) to ApiClient.objectMapper.writeValueAsBytes(mapOf("lastName" to p.lastName, "firstName" to p.firstName))
            },
            unmarshaller = { p, c ->
                PatientMapperFactory.instance.map(
                    p.copy(
                        lastName = ApiClient.objectMapper.readTree(c).get("lastName")?.textValue(),
                        firstName = ApiClient.objectMapper.readTree(c).get("firstName")?.textValue()
                    )
                )
            }
        )

    @org.junit.jupiter.api.Test
    fun encryptPatient() {
    }

    @org.junit.jupiter.api.Test
    fun decryptPatient() {
    }
}
