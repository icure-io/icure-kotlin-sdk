package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.DocumentApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.documentCryptoConfig
import io.icure.kraken.client.crypto.toPrivateKey
import io.icure.kraken.client.extendedapis.infrastructure.ExtendedTestUtils.localCrypto
import io.icure.kraken.client.models.decrypted.DocumentDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Paths
import java.util.*

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
internal class DocumentApiKtTest {
    private val iCureBackendUrl = System.getenv("ICURE_BE_URL") ?: "https://kraken.icure.dev"

    private val parentAuthorization = "Basic " + Base64.getEncoder().encodeToString("${System.getenv("PARENT_HCP_USERNAME")}:${System.getenv("PARENT_HCP_PASSWORD")}".toByteArray(Charsets.UTF_8))
    private val parentPrivKey = System.getenv("PARENT_HCP_PRIV_KEY").toPrivateKey()
    
    private val userApi = UserApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val hcpartyApi = HealthcarePartyApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)
    private val documentApi = DocumentApi(basePath = iCureBackendUrl, authHeader = parentAuthorization)

    @FlowPreview
    @Test
    fun setDocumentAttachment_HappyFlow() {
        runBlocking {
            // Init
            val currentUser = userApi.getCurrentUser()
            val hcp = hcpartyApi.getCurrentHealthcareParty()

            val localCrypto = localCrypto(iCureBackendUrl,
                parentAuthorization, parentPrivKey, currentUser, hcp.toDataOwner())
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
}
