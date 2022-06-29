package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.DeviceApi
import io.icure.kraken.client.apis.HealthElementApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.MaintenanceTaskApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.healthElementCryptoConfig
import io.icure.kraken.client.crypto.patientCryptoConfig
import io.icure.kraken.client.crypto.toPrivateKey
import io.icure.kraken.client.crypto.toPublicKey
import io.icure.kraken.client.extendedapis.infrastructure.ExtendedTestUtils.dataOwnerWrapperFor
import io.icure.kraken.client.extendedapis.infrastructure.createHealthcareParty
import io.icure.kraken.client.extendedapis.infrastructure.createUserForHcp
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.HealthElementDto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@OptIn(ExperimentalUnsignedTypes::class)
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
@FlowPreview
internal class HealthElementApiKtTest {
    private val iCureBackendUrl = System.getenv("ICURE_BE_URL") ?: "https://kraken.icure.dev"

    private val parentAuthorization = "Basic " + Base64.getEncoder().encodeToString(
        "${System.getenv("PARENT_HCP_USERNAME")}:${System.getenv("PARENT_HCP_PASSWORD")}".toByteArray(Charsets.UTF_8)
    )

    private val parentPrivKey = System.getenv("PARENT_HCP_PRIV_KEY").toPrivateKey()

    private val userApi = UserApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val hcPartyApi = HealthcarePartyApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val healthElementApi = HealthElementApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val maintenanceTaskApi = MaintenanceTaskApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val deviceApi = DeviceApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val patientApi = PatientApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)

    @Test
    fun `old hcp giveAccess to newly created Health Element to hcp1`() = runBlocking {
        val parentUser = userApi.getCurrentUser()
        val parent = hcPartyApi.getCurrentHealthcareParty()
        val parentLocalCrypto = LocalCrypto(
            dataOwnerWrapperFor(iCureBackendUrl, parentAuthorization), mapOf(
                parent.id to listOf(parentPrivKey to parent.publicKey!!.toPublicKey()),
            ),
            maintenanceTaskApi
        )

        val hcp1Kp = CryptoUtils.generateKeyPairRSA()

        val hcp1User = userApi.createUserForHcp(
            hcPartyApi.createHealthcareParty(parentUser, parentLocalCrypto, hcp1Kp, "Bender Bending", "Rodriguez"),
            parent
        )

        val hcp1Auth =
            "Basic ${Base64.getEncoder().encodeToString("${hcp1User.login}:test".toByteArray(Charsets.UTF_8))}"

        val hcp1ContactApi = HealthElementApi(basePath = iCureBackendUrl, authHeader = hcp1Auth)

        val ccHealthElement = { auth: String, user: UserDto, kp: KeyPair ->
            healthElementCryptoConfig(
                LocalCrypto(
                    dataOwnerWrapperFor(
                        iCureBackendUrl,
                        auth
                    ), mapOf(
                        user.dataOwnerId() to listOf(kp.private as RSAPrivateKey to kp.public as RSAPublicKey)
                    )
                )
            )
        }

        val hcp1HealthElementCryptoConfig = ccHealthElement(hcp1Auth, hcp1User, hcp1Kp)
        val parentHealthElementCryptoConfig = healthElementCryptoConfig(parentLocalCrypto)
        val parentPatientCryptoConfig = patientCryptoConfig(parentLocalCrypto)

        delay(4000)

        // When
        val createdPatient = try {
            patientApi.createPatient(
                parentUser,
                PatientDto(
                    id = UUID.randomUUID().toString(),
                    firstName = "Hermez",
                    lastName = "Conrad",
                    note = "Sweet manatee of Galilee!"
                ),
                parentPatientCryptoConfig
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        val healthElementDto = try {
            healthElementApi.createHealthElement(
                user = parentUser,
                patient = createdPatient,
                healthElement = healthElementToCreate(),
                config = parentHealthElementCryptoConfig
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertNotNull(healthElementDto, "Health Element should not be null")

        val sharedHealthElement = healthElementApi.giveAccessTo(
            parentHealthElementCryptoConfig,
            parentUser,
            healthElementDto,
            hcp1User.dataOwnerId()
        )

        val gotHealthElement = try {
            hcp1ContactApi.getHealthElement(hcp1User, sharedHealthElement.id, hcp1HealthElementCryptoConfig)
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertEquals(sharedHealthElement, gotHealthElement)
    }

    @Test
    fun `hcp1 giveAccess to newly created patient to hcp2`() = runBlocking {
        val parentUser = userApi.getCurrentUser()
        val parent = hcPartyApi.getCurrentHealthcareParty()
        val parentLocalCrypto = LocalCrypto(
            dataOwnerWrapperFor(iCureBackendUrl, parentAuthorization), mapOf(
                parent.id to listOf(parentPrivKey to parent.publicKey!!.toPublicKey()),
            ),
            maintenanceTaskApi
        )

        val hcp1Kp = CryptoUtils.generateKeyPairRSA()
        val hcp2Kp = CryptoUtils.generateKeyPairRSA()

        val hcp1User = userApi.createUserForHcp(
            hcPartyApi.createHealthcareParty(parentUser, parentLocalCrypto, hcp1Kp, "Bender Bending", "Rodriguez"),
            parent
        )
        val hcp2User = userApi.createUserForHcp(
            hcPartyApi.createHealthcareParty(parentUser, parentLocalCrypto, hcp2Kp, "Philip J.", "Fry"),
            parent
        )

        val hcp1Auth =
            "Basic ${Base64.getEncoder().encodeToString("${hcp1User.login}:test".toByteArray(Charsets.UTF_8))}"
        val hcp2Auth =
            "Basic ${Base64.getEncoder().encodeToString("${hcp2User.login}:test".toByteArray(Charsets.UTF_8))}"

        val hcp1PatientApi = PatientApi(basePath = iCureBackendUrl, authHeader = hcp1Auth)
        val hcp1HealthElementApi = HealthElementApi(basePath = iCureBackendUrl, authHeader = hcp1Auth)
        val hcp2HealthElementApi = HealthElementApi(basePath = iCureBackendUrl, authHeader = hcp2Auth)

        val localCrypto = { auth: String, user: UserDto, kp: KeyPair ->
            LocalCrypto(
                dataOwnerWrapperFor(
                    iCureBackendUrl,
                    auth
                ), mapOf(
                    user.dataOwnerId() to listOf(kp.private as RSAPrivateKey to kp.public as RSAPublicKey)
                )
            )
        }

        val hcp1LocalCrypto = localCrypto(hcp1Auth, hcp1User, hcp1Kp)
        val hcp2LocalCrypto = localCrypto(hcp2Auth, hcp2User, hcp2Kp)

        val hcp1HealthElementCryptoConfig = healthElementCryptoConfig(hcp1LocalCrypto)
        val hcp2HealthElementCryptoConfig = healthElementCryptoConfig(hcp2LocalCrypto)
        val hcp1PatientCryptoConfig = patientCryptoConfig(hcp1LocalCrypto)

        delay(4000)

        // When
        val createdPatient = try {
            hcp1PatientApi.createPatient(
                hcp1User,
                PatientDto(
                    id = UUID.randomUUID().toString(),
                    firstName = "Hermez",
                    lastName = "Conrad",
                    note = "Sweet manatee of Galilee!"
                ),
                hcp1PatientCryptoConfig
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertNotNull(createdPatient, "Patient should not be null")

        val createdHealthElement = try {
            hcp1HealthElementApi.createHealthElement(
                user = hcp1User,
                patient = createdPatient,
                healthElement = healthElementToCreate(),
                config = hcp1HealthElementCryptoConfig
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertNotNull(createdHealthElement, "Contact should not be null")

        val sharedHealthElement = hcp1HealthElementApi.giveAccessTo(
            hcp1HealthElementCryptoConfig,
            hcp1User,
            createdHealthElement,
            hcp2User.dataOwnerId()
        )

        val gotHealthElement = try {
            hcp2HealthElementApi.getHealthElement(hcp2User, sharedHealthElement.id, hcp2HealthElementCryptoConfig)
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertEquals(sharedHealthElement, gotHealthElement)
    }

    private fun healthElementToCreate(
        healthElementId: String = UUID.randomUUID().toString(),
    ) = HealthElementDto(
        id = healthElementId,
        openingDate = 20220629,
        closingDate = 20220629153600,
        descr = "HealthElement du 29/06/2020",
        medicalLocationId = UUID.randomUUID().toString(),
        status = 0,
        relevant = true
    )

}
