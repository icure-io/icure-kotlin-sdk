package io.icure.kraken.client.extendedapis

import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.crypto.CryptoUtils
import io.icure.kraken.client.crypto.privateKeyAsString
import io.icure.kraken.client.crypto.publicKeyAsString
import io.icure.kraken.client.models.AuthenticationTokenDto
import io.icure.kraken.client.models.HealthcarePartyDto
import io.icure.kraken.client.models.UserDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.nio.file.Path
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

    @Test
    internal fun createHcPartyTest() = runBlocking {
        val parent = hcpartyApi.getCurrentHealthcareParty()

        val kp = CryptoUtils.generateKeyPairRSA()

        val newHcp = hcpartyApi.createHealthcareParty(HealthcarePartyDto(id = UUID.randomUUID().toString(), firstName = "Jimmy", lastName = "Materazzi", publicKey = kp.publicKeyAsString(), parentId = parent.id).initHcparty())
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
    }
}
