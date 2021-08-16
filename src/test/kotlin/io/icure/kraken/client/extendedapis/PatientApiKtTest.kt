package io.icure.kraken.client.extendedapis

import com.fasterxml.jackson.databind.ObjectMapper
import io.icure.kraken.client.apis.HcpartyApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.CryptoConfig
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.CryptoUtils.toPrivateKey
import io.icure.kraken.client.crypto.CryptoUtils.toPublicKey
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.models.decrypted.PatientDto
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import java.util.*

@DelicateCoroutinesApi
@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
internal class PatientApiKtTest {
    val objectMapper = ObjectMapper()
    val userApi = UserApi(basePath = "https://kraken.svc.icure.cloud/rest/v1", authHeader = "Basic YWJkZW1vOmtuYWxvdQo=")
    val hcpartyApi = HcpartyApi(basePath = "https://kraken.svc.icure.cloud/rest/v1", authHeader = "Basic YWJkZW1vOmtuYWxvdQo=")
    val patientApi = PatientApi(basePath = "https://kraken.svc.icure.cloud/rest/v1", authHeader = "Basic YWJkZW1vOmtuYWxvdQo=")

    @org.junit.jupiter.api.Test
    fun createPatient() = runBlocking {
        val user = userApi.getCurrentUser()!!
        val hcp = hcpartyApi.getCurrentHealthcareParty()!!
        val cc = CryptoConfig<PatientDto>(
            crypto = LocalCrypto(hcpartyApi, mapOf(
                user.healthcarePartyId!! to (toPrivateKey(this::class.java.getResource("keys/${hcp.id}-icc-priv.2048.key").readText(Charsets.UTF_8)) to toPublicKey(hcp.publicKey!!))
            )),
            marshaller = { p -> p.copy(note = null) to objectMapper.writeValueAsBytes(mapOf("note" to p.note))},
            unmarshaller = { p, c -> p.copy(note = objectMapper.readTree(c).get("note")?.textValue()) }
        )
        val p = patientApi.createPatient(user, PatientDto(id = UUID.randomUUID().toString(), firstName = "John", lastName = "Doe", note = "To be encrypted"), cc)


    }

    @org.junit.jupiter.api.Test
    fun encryptPatient() {
    }

    @org.junit.jupiter.api.Test
    fun decryptPatient() {
    }
}
