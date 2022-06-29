package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.ContactApi
import io.icure.kraken.client.apis.DeviceApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.MaintenanceTaskApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.contactCryptoConfig
import io.icure.kraken.client.crypto.patientCryptoConfig
import io.icure.kraken.client.crypto.toPrivateKey
import io.icure.kraken.client.crypto.toPublicKey
import io.icure.kraken.client.extendedapis.infrastructure.ExtendedTestUtils.dataOwnerWrapperFor
import io.icure.kraken.client.extendedapis.infrastructure.ExtendedTestUtils.localCrypto
import io.icure.kraken.client.extendedapis.infrastructure.createHealthcareParty
import io.icure.kraken.client.extendedapis.infrastructure.createUserForHcp
import io.icure.kraken.client.extendedapis.mapper.ContactMapperFactory
import io.icure.kraken.client.infrastructure.ApiClient
import io.icure.kraken.client.models.CodeStubDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.ContactDto
import io.icure.kraken.client.models.decrypted.ContentDto
import io.icure.kraken.client.models.decrypted.PatientDto
import io.icure.kraken.client.models.decrypted.ServiceDto
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
internal class ContactApiKtTest {
    private val iCureBackendUrl = System.getenv("ICURE_BE_URL") ?: "https://kraken.icure.dev"

    private val parentAuthorization = "Basic " + Base64.getEncoder().encodeToString("${System.getenv("PARENT_HCP_USERNAME")}:${System.getenv("PARENT_HCP_PASSWORD")}".toByteArray(Charsets.UTF_8))
    private val child1Authorization = "Basic " + Base64.getEncoder().encodeToString(
        "${System.getenv("CHILD_1_HCP_USERNAME")}:${System.getenv("CHILD_1_HCP_PASSWORD")}".toByteArray(Charsets.UTF_8)
    )
    private val child2Authorization = "Basic " + Base64.getEncoder().encodeToString(
        "${System.getenv("CHILD_2_HCP_USERNAME")}:${System.getenv("CHILD_2_HCP_PASSWORD")}".toByteArray(Charsets.UTF_8)
    )

    private val parentPrivKey = System.getenv("PARENT_HCP_PRIV_KEY").toPrivateKey()
    private val child1PrivKey = System.getenv("CHILD_1_HCP_PRIV_KEY").toPrivateKey()
    private val child2PrivKey = System.getenv("CHILD_2_HCP_PRIV_KEY").toPrivateKey()

    private val userApi = UserApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val hcPartyApi = HealthcarePartyApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val contactApi = ContactApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val maintenanceTaskApi = MaintenanceTaskApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val deviceApi = DeviceApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val patientApi = PatientApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)

    private val child1UserApi = UserApi(basePath = iCureBackendUrl, authHeader = child1Authorization)
    private val child1HealthcarePartyApi =
        HealthcarePartyApi(basePath = iCureBackendUrl, authHeader = child1Authorization)
    private val child1ContactApi = ContactApi(basePath = iCureBackendUrl, authHeader = child1Authorization)
    private val child1PatientApi = PatientApi(basePath = iCureBackendUrl, authHeader = child1Authorization)

    private val child2UserApi = UserApi(basePath = iCureBackendUrl, authHeader = child2Authorization)
    private val child2HealthcarePartyApi =
        HealthcarePartyApi(basePath = iCureBackendUrl, authHeader = child2Authorization)
    private val child2ContactApi = ContactApi(basePath = iCureBackendUrl, authHeader = child2Authorization)

    @Test
    fun testCreateContactUsingDefaultCryptoConfig() = runBlocking {
        val contactToCreateId = UUID.randomUUID().toString()

        // before
        val user = userApi.getCurrentUser()
        val hcp = hcPartyApi.getCurrentHealthcareParty()
        val cc = contactCryptoConfig(localCrypto(iCureBackendUrl,
            parentAuthorization, parentPrivKey, user, hcp.toDataOwner()), user)

        val contactToCreate = contactToCreate(contactToCreateId)

        // when
        val contact = contactApi.createContact(user, contactToCreate, cc)

        // then
        Assertions.assertNotNull(contact, "Contact couldn't be found")
        Assertions.assertNotNull(contact.services.first().encryptedSelf, "Service content should be encrypted")
        Assertions.assertNotNull(contact.encryptionKeys, "Contact encryption keys should not be null")
        Assertions.assertNotNull(contact.encryptedSelf, "Contact content should be encrypted")
        Assertions.assertEquals(contact.services.first().content["fr"]?.numberValue,
            contactToCreate.services.first().content["fr"]?.numberValue,
            "Service content should not be null"
        )

        val encryptedContact = contactApi.getContact(contactToCreateId)
        Assertions.assertEquals(encryptedContact.services.first().content.isEmpty(), true, "Service content should only be encrypted")
        Assertions.assertNotNull(encryptedContact.services.first().encryptedSelf, "Service content should be encrypted")
    }

    @Test
    fun createContactWithDefaultCryptoConfigHcpWithParent() = runBlocking {
        val parent = userApi.getCurrentUser()
        val parentHcp = hcPartyApi.getCurrentHealthcareParty()

        // Before
        val user1 = child1UserApi.getCurrentUser()
        val hcp1 = child1HealthcarePartyApi.getCurrentHealthcareParty()

        val user2 = child2UserApi.getCurrentUser()
        val hcp2 = child2HealthcarePartyApi.getCurrentHealthcareParty()

        Assertions.assertNotNull(hcp1.parentId, "Hcp must have a parent for this test")
        Assertions.assertNotNull(hcp2.parentId, "Hcp must have a parent for this test")

        val cc1 = contactCryptoConfig(LocalCrypto(
            dataOwnerWrapperFor(iCureBackendUrl, child1Authorization), mapOf(
                parent.healthcarePartyId!! to listOf(parentPrivKey to parentHcp.publicKey!!.toPublicKey()),
                user1.healthcarePartyId!! to listOf(child1PrivKey to hcp1.publicKey!!.toPublicKey())
            )
        ), user1)

        val cc2 = contactCryptoConfig(LocalCrypto(
            dataOwnerWrapperFor(iCureBackendUrl, child2Authorization), mapOf(
                parent.healthcarePartyId!! to listOf(parentPrivKey to parentHcp.publicKey!!.toPublicKey()),
                user2.healthcarePartyId!! to listOf(child2PrivKey to hcp2.publicKey!!.toPublicKey())
            )
        ), user2)

        val pcc = patientCryptoConfig(LocalCrypto(
            dataOwnerWrapperFor(iCureBackendUrl, child1Authorization), mapOf(
                parent.healthcarePartyId!! to listOf(parentPrivKey to parentHcp.publicKey!!.toPublicKey()),
                user1.healthcarePartyId!! to listOf(child1PrivKey to hcp1.publicKey!!.toPublicKey())
            )
        ))

        val p = try { child1PatientApi.createPatient(user1, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), pcc) } catch(e:Exception) { throw IllegalStateException(e) }

        // When
        val p1 = try { child1ContactApi.createContact(user1, p, contactToCreate(), cc1) } catch(e:Exception) { throw IllegalStateException(e) }
        try { child2ContactApi.createContact(user2, p, contactToCreate(), cc2) } catch(e:Exception) { throw IllegalStateException(e) }

        val ctcs1 = child1ContactApi.findByHCPartyPatient(user1, hcp1.id, p, null, null, cc1)
        val ctcs2 = child1ContactApi.findByHCPartyPatient(user2, hcp2.id, p, null, null, cc2)
        val ctcsp1 = child1ContactApi.findByHCPartyPatient(user1, hcp1.parentId!!, p, null, null, cc1)
        val ctcsp2 = child1ContactApi.findByHCPartyPatient(user2, hcp2.parentId!!, p, null, null, cc2)

        // Then
        Assertions.assertNotNull(p1, "Patient should not be null")
        Assertions.assertEquals(ctcs1.size, 1)
        Assertions.assertEquals(ctcs2.size, 1)
        Assertions.assertEquals(ctcsp1.size, 2)
        Assertions.assertEquals(ctcsp1, ctcsp2)
    }

    @Test
    fun testCreateContactUsingCustomCryptoConfig() = runBlocking {
        val contactToCreateId = UUID.randomUUID().toString()

        // before
        val user = userApi.getCurrentUser()
        val hcp = hcPartyApi.getCurrentHealthcareParty()
        val cc = customContactCrypto(localCrypto(iCureBackendUrl, parentAuthorization, parentPrivKey, user, hcp.toDataOwner()))

        val contactToCreate = contactToCreate(contactToCreateId)

        // when
        val contact = contactApi.createContact(user, contactToCreate, cc)

        // then
        Assertions.assertNotNull(contact, "Contact couldn't be found")
        Assertions.assertEquals(contact.descr, contactToCreate.descr, "Descr should not be encrypted")
        Assertions.assertEquals(contact.medicalLocationId, contactToCreate.medicalLocationId, "Medical Location Id should not be encrypted")
        Assertions.assertNotNull(contact.encryptionKeys, "Contact encryption keys should not be null")
        Assertions.assertNotNull(contact.encryptedSelf, "Contact content should be encrypted")

        val encryptedContact = contactApi.getContact(contactToCreateId)
        Assertions.assertNull(encryptedContact.descr, "Descr should be encrypted")
        Assertions.assertNull(encryptedContact.medicalLocationId, "Medical Location Id should be encrypted")

        Assertions.assertNull(encryptedContact.services.first().encryptedSelf, "Service should not be encrypted")
        Assertions.assertEquals(
            encryptedContact.services.first().content["fr"]?.numberValue,
            contactToCreate.services.first().content["fr"]?.numberValue,
            "Service content should not be encrypted"
        )
    }

    @Test
    fun `old hcp giveAccess to newly created Contact to hcp1`() = runBlocking {
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

        val hcp1ContactApi = ContactApi(basePath = iCureBackendUrl, authHeader = hcp1Auth)

        val ccContact = { auth: String, user: UserDto, kp: KeyPair ->
            contactCryptoConfig(
                LocalCrypto(
                    dataOwnerWrapperFor(
                        iCureBackendUrl,
                        auth
                    ), mapOf(
                        user.dataOwnerId() to listOf(kp.private as RSAPrivateKey to kp.public as RSAPublicKey)
                    )
                ),
                user
            )
        }

        val cc1 = ccContact(hcp1Auth, hcp1User, hcp1Kp)
        val ccParentContact = contactCryptoConfig(parentLocalCrypto, parentUser)
        val ccParentPatient = patientCryptoConfig(parentLocalCrypto)

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
                ccParentPatient
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        val c1 = try {
            contactApi.createContact(
                user = parentUser,
                patient = p1,
                contact = contactToCreate(),
                config = ccParentContact
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertNotNull(c1, "Contact should not be null")

        val sharedC1 = contactApi.giveAccessTo(ccParentContact, parentUser, c1, hcp1User.dataOwnerId())

        val c2 = try {
            hcp1ContactApi.getContact(hcp1User, sharedC1.id, cc1)
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertEquals(sharedC1.descr, c2.descr)
        Assertions.assertEquals(sharedC1.id, c2.id)
        Assertions.assertEquals(sharedC1.rev, c2.rev)
        Assertions.assertEquals(sharedC1.services.firstOrNull()?.content, c2.services.firstOrNull()?.content)
    }

    @Test
    fun `hcp1 giveAccess to newly created Contact to hcp2`() = runBlocking {
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
        val hcp1ContactApi = ContactApi(basePath = iCureBackendUrl, authHeader = hcp1Auth)
        val hcp2ContactApi = ContactApi(basePath = iCureBackendUrl, authHeader = hcp2Auth)

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

        val hcp1ContactCryptoConfig = contactCryptoConfig(hcp1LocalCrypto, hcp1User)
        val hcp2ContactCryptoConfig = contactCryptoConfig(hcp2LocalCrypto, hcp2User)
        val hcp1PatientCryptoConfig = patientCryptoConfig(hcp1LocalCrypto)

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
                hcp1PatientCryptoConfig
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertNotNull(p1, "Patient should not be null")

        val c1 = try {
            hcp1ContactApi.createContact(
                user = hcp1User,
                patient = p1,
                contact = contactToCreate(),
                config = hcp1ContactCryptoConfig
            )
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertNotNull(c1, "Contact should not be null")

        val sharedC1 = hcp1ContactApi.giveAccessTo(hcp1ContactCryptoConfig, hcp1User, c1, hcp2User.dataOwnerId())

        val c2 = try {
            hcp2ContactApi.getContact(hcp2User, sharedC1.id, hcp2ContactCryptoConfig)
        } catch (e: Exception) {
            throw IllegalStateException(e)
        }

        Assertions.assertEquals(sharedC1.descr, c2.descr)
        Assertions.assertEquals(sharedC1.id, c2.id)
        Assertions.assertEquals(sharedC1.rev, c2.rev)
        Assertions.assertEquals(sharedC1.services.firstOrNull()?.content, c2.services.firstOrNull()?.content)
    }

    private fun contactToCreate(
        contactId: String = UUID.randomUUID().toString(),
    ) = ContactDto(
        id = contactId,
        openingDate = 20171214,
        closingDate = 20171214153600,
        descr = "Contact du 14/12/17",
        medicalLocationId = UUID.randomUUID().toString(),
        services = listOf(
            ServiceDto(
                id = UUID.randomUUID().toString(),
                label = "BMI",
                index = 2,
                content = mapOf("fr" to ContentDto(numberValue = 0.0)),
                tags = listOf(
                    CodeStubDto(id = "SOAP|Objective|1", type = "SOAP", code = "Objective", version = "1"),
                    CodeStubDto(id = "CD-ITEM|parameter|1", type = "CD-ITEM", code = "parameter", version = "1"),
                    CodeStubDto(id = "CD-PARAMETER|bmi|1", type = "CD-PARAMETER", code = "bmi", version = "1")
                )
            )
        )
    )

    private fun customContactCrypto(crypto: LocalCrypto) =
        CryptoConfig<ContactDto, io.icure.kraken.client.models.ContactDto>(
            crypto = crypto,
            marshaller = { c ->
                ContactMapperFactory.instance.map(c).copy(
                    descr = null,
                    medicalLocationId = null
                ) to ApiClient.objectMapper.writeValueAsBytes(mapOf(
                    "descr" to c.descr,
                    "medicalLocationId" to c.medicalLocationId
                ))
            },
            unmarshaller = { c, b ->
                ContactMapperFactory.instance.map(c).copy(
                    descr = ApiClient.objectMapper.readTree(b).get("descr")?.textValue(),
                    medicalLocationId = ApiClient.objectMapper.readTree(b).get("medicalLocationId")?.textValue()
                )
            }
        )
}
