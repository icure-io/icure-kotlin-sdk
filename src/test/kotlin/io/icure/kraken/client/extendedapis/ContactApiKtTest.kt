package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.ContactApi
import io.icure.kraken.client.apis.HcpartyApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.contactCryptoConfig
import io.icure.kraken.client.extendedapis.infrastructure.ExtendedTestUtils
import io.icure.kraken.client.infrastructure.ApiClient
import io.icure.kraken.client.models.CodeStubDto
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.ContactDto
import io.icure.kraken.client.models.decrypted.ContentDto
import io.icure.kraken.client.models.decrypted.ServiceDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.net.URL
import java.util.*

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
internal class ContactApiKtTest {
    private val userApi = UserApi(basePath = "http://127.0.0.1:16043", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val hcPartyApi = HcpartyApi(basePath = "http://127.0.0.1:16043", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")
    private val contactApi = ContactApi(basePath = "http://127.0.0.1:16043", authHeader = "Basic YWJkZW1vdHN0MjoyN2I5MGY2ZS02ODQ3LTQ0YmYtYjkwZi02ZTY4NDdiNGJmMWM=")

    @Test
    fun testCreateContactUsingDefaultCryptoConfig() = runBlocking {
        val contactToCreateId = UUID.randomUUID().toString()

        try {
            // before
            val user = userApi.getCurrentUser()
            val hcp = hcPartyApi.getCurrentHealthcareParty()
            val keyPath = "keys/${hcp.id}-icc-priv.2048.key"
            val keyFile = ContactApiKtTest::class.java.getResource(keyPath)!!
            val cc = contactCryptoConfig(localCrypto(keyFile, user, hcp), user)

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

        } finally {
            ExtendedTestUtils.deleteElements("healthdata", listOf(contactToCreateId))
        }
    }

    @Test
    fun testCreateContactUsingCustomCryptoConfig() = runBlocking {
        val contactToCreateId = UUID.randomUUID().toString()

        try {
            // before
            val user = userApi.getCurrentUser()
            val hcp = hcPartyApi.getCurrentHealthcareParty()
            val keyPath = "keys/${hcp.id}-icc-priv.2048.key"
            val keyFile = ContactApiKtTest::class.java.getResource(keyPath)!!
            val cc = customContactCrypto(localCrypto(keyFile, user, hcp))

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
            Assertions.assertEquals(encryptedContact.services.first().content["fr"]?.numberValue,
                contactToCreate.services.first().content["fr"]?.numberValue,
                "Service content should not be encrypted"
            )

        } finally {
            ExtendedTestUtils.deleteElements("healthdata", listOf(contactToCreateId))
        }
    }

    private fun contactToCreate(contactId: String = UUID.randomUUID().toString()) = ContactDto(
        id = contactId,
        openingDate = 20171214,
        closingDate = 20171214153600,
        descr = "Contact du 14/12/17",
        medicalLocationId = UUID.randomUUID().toString(),
        healthcarePartyId = "782f1bcd-9f3f-408a-af1b-cd9f3f908a98",
        services = listOf(
            ServiceDto(
                id = UUID.randomUUID().toString(),
                label = "BMI",
                index = 2,
                content = mapOf("fr" to ContentDto(numberValue = 0.0)),
                valueDate = 20170515151507,
                created = 1494854114248,
                modified = 1494854114105,
                author = "ebd30407-9f33-4cd5-9999-079f334cd5e8",
                responsible = "782f1bcd-9f3f-408a-af1b-cd9f3f908a98",
                tags = listOf(
                    CodeStubDto(id = "SOAP|Objective|1", type = "SOAP", code = "Objective", version = "1"),
                    CodeStubDto(id = "CD-ITEM|parameter|1", type = "CD-ITEM", code = "parameter", version = "1"),
                    CodeStubDto(id = "CD-PARAMETER|bmi|1", type = "CD-PARAMETER", code = "bmi", version = "1")
                )
            )
        )
    )

    private fun localCrypto(keyFile: URL,
                            user: UserDto,
                            hcp: HealthcarePartyDto) : LocalCrypto {
        return LocalCrypto(
            hcPartyApi, mapOf(
                user.healthcarePartyId!! to (CryptoUtils.toPrivateKey(keyFile.readText(Charsets.UTF_8)) to CryptoUtils.toPublicKey(
                    hcp.publicKey!!
                ))
            )
        )
    }

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