package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.DocumentApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.documentCryptoConfig
import io.icure.kraken.client.crypto.toPrivateKey
import io.icure.kraken.client.crypto.toPublicKey
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.decrypted.DocumentDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.net.URL
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Paths
import java.util.*

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
internal class DocumentApiKtTest {
    private val userApi =
        UserApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic YWJkZW1vOmtuYWxvdQ==")
    private val hcpartyApi =
        HealthcarePartyApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic YWJkZW1vOmtuYWxvdQ==")
    private val documentApi =
        DocumentApi(basePath = "https://kraken.svc.icure.cloud", authHeader = "Basic YWJkZW1vOmtuYWxvdQ==")

    @org.junit.jupiter.api.Test
    fun setDocumentAttachment_HappyFlow() {
        runBlocking {
            // Init
            val currentUser = userApi.getCurrentUser()
            val hcp = hcpartyApi.getCurrentHealthcareParty()

            val keyPath = "keys/${hcp.id}-icc-priv.2048.key"
            val keyFile = this@DocumentApiKtTest::class.java.getResource(keyPath)!!
            val localCrypto = localCrypto(currentUser, keyFile, hcp)
            val documentConfig = documentCryptoConfig(localCrypto)

            val attachmentToAdd = Files.readAllBytes(Paths.get("src/test/resources/set_attachment_test.txt"))
            val documentToCreate = DocumentDto(
                id = UUID.randomUUID().toString(),
                name = "set_attachment_test",
                version = "1.0.0",
                externalUuid = UUID.randomUUID().toString()
            )

            val createdDocument = documentApi.createDocument(currentUser, documentToCreate, documentConfig)
            val docEncKeys = localCrypto.decryptEncryptionKeys(currentUser.healthcarePartyId!!, createdDocument.encryptionKeys)

            // When
            val docWithAttachment = documentApi.setDocumentAttachment(
                user = currentUser,
                documentId = createdDocument.id,
                requestBody = flowOf(ByteBuffer.wrap(attachmentToAdd)),
                enckeys = docEncKeys.firstOrNull(),
                config = documentConfig
            )

            // Then
            assert(docWithAttachment.attachmentId != null)
            Assertions.assertEquals(docWithAttachment.name, documentToCreate.name)
            Assertions.assertEquals(docWithAttachment.version, documentToCreate.version)
            Assertions.assertEquals(docWithAttachment.externalUuid, documentToCreate.externalUuid)
        }
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
}