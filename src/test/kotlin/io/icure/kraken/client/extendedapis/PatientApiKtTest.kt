package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.HcpartyApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.patientCryptoConfig
import io.icure.kraken.client.crypto.toPrivateKey
import io.icure.kraken.client.crypto.toPublicKey
import io.icure.kraken.client.infrastructure.ApiClient
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import java.net.URL
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
internal class PatientApiKtTest {
    private val userApi = UserApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic YWJkZW1vOmtuYWxvdQ==")
    private val hcpartyApi = HcpartyApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic YWJkZW1vOmtuYWxvdQ==")
    private val patientApi = PatientApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic YWJkZW1vOmtuYWxvdQ==")

    private val child1UserApi = UserApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic ${Base64.getEncoder().encodeToString("jimmy-1643812116186:test".toByteArray(kotlin.text.Charsets.UTF_8))}")
    private val child1HcpartyApi = HcpartyApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic ${Base64.getEncoder().encodeToString("jimmy-1643812116186:test".toByteArray(kotlin.text.Charsets.UTF_8))}")
    private val child1PatientApi = PatientApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic ${Base64.getEncoder().encodeToString("jimmy-1643812116186:test".toByteArray(kotlin.text.Charsets.UTF_8))}")

    private val child2UserApi = UserApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic ${Base64.getEncoder().encodeToString("jimmy-1643812213976:test".toByteArray(kotlin.text.Charsets.UTF_8))}")
    private val child2HcpartyApi = HcpartyApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic ${Base64.getEncoder().encodeToString("jimmy-1643812213976:test".toByteArray(kotlin.text.Charsets.UTF_8))}")
    private val child2PatientApi = PatientApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic ${Base64.getEncoder().encodeToString("jimmy-1643812213976:test".toByteArray(kotlin.text.Charsets.UTF_8))}")

    @org.junit.jupiter.api.Test
    fun createPatientWithDefaultCryptoConfig() = runBlocking {
        // Before
        val user = userApi.getCurrentUser()
        val hcp = hcpartyApi.getCurrentHealthcareParty()

        val keyPath = "keys/${hcp.id}-icc-priv.2048.key"
        val keyFile = PatientApiKtTest::class.java.getResource(keyPath)!!
        val cc = patientCryptoConfig(localCrypto(user, keyFile, hcp))

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

    @org.junit.jupiter.api.Test
    fun createPatientWithDefaultCryptoConfigHcpWithParent() = runBlocking {
        val parent = userApi.getCurrentUser()
        val parentHcp = hcpartyApi.getCurrentHealthcareParty()
        val keyPath = "keys/${parent.healthcarePartyId}-icc-priv.2048.key"
        val keyFile = PatientApiKtTest::class.java.getResource(keyPath)!!

        // Before
        val user1 = child1UserApi.getCurrentUser()
        val hcp1 = child1HcpartyApi.getCurrentHealthcareParty()

        val user2 = child2UserApi.getCurrentUser()
        val hcp2 = child2HcpartyApi.getCurrentHealthcareParty()

        Assertions.assertNotNull(hcp1.parentId, "Hcp must have a parent for this test")
        Assertions.assertNotNull(hcp2.parentId, "Hcp must have a parent for this test")

        val keyPath1 = "keys/${hcp1.id}-icc-priv.2048.key"
        val keyFile1 = PatientApiKtTest::class.java.getResource(keyPath1)!!
        val cc1 = patientCryptoConfig(LocalCrypto(
            child1HcpartyApi, mapOf(
                parent.healthcarePartyId!! to (keyFile.readText(Charsets.UTF_8).toPrivateKey() to parentHcp.publicKey!!.toPublicKey()),
                user1.healthcarePartyId!! to (keyFile1.readText(Charsets.UTF_8).toPrivateKey() to hcp1.publicKey!!.toPublicKey())
            )
        ))

        val keyPath2 = "keys/${hcp2.id}-icc-priv.2048.key"
        val keyFile2 = PatientApiKtTest::class.java.getResource(keyPath2)!!
        val cc2 = patientCryptoConfig(LocalCrypto(
            child2HcpartyApi, mapOf(
                parent.healthcarePartyId!! to (keyFile.readText(Charsets.UTF_8).toPrivateKey() to parentHcp.publicKey!!.toPublicKey()),
                user2.healthcarePartyId!! to (keyFile2.readText(Charsets.UTF_8).toPrivateKey() to hcp2.publicKey!!.toPublicKey())
            )
        ))

        // When
        val p1 = try { child1PatientApi.createPatient(user1, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), cc1) } catch(e:Exception) { throw IllegalStateException(e) }
        val p2 = try { child2PatientApi.getPatient(user2, p1.id, cc2) } catch(e:Exception) { throw IllegalStateException(e) }

        // Then
        Assertions.assertNotNull(p1, "Patient should not be null")
        Assertions.assertEquals(p1.note, p2.note)
    }


    @org.junit.jupiter.api.Test
    fun createPatientWithCustomCryptoConfig() = runBlocking {
        // Before
        val user = userApi.getCurrentUser()
        val hcp = hcpartyApi.getCurrentHealthcareParty()
        val keyPath = "keys/${hcp.id}-icc-priv.2048.key"
        val keyFile = PatientApiKtTest::class.java.getResource(keyPath)!!
        val cc = customPatientCryptoConfig(localCrypto(user, keyFile, hcp))

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

    private fun localCrypto(
        user: UserDto,
        keyFile: URL,
        hcp: HealthcarePartyDto
    ) = LocalCrypto(
        hcpartyApi, mapOf(
            user.healthcarePartyId!! to (keyFile.readText(Charsets.UTF_8).toPrivateKey() to hcp.publicKey!!.toPublicKey())
        )
    )

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
