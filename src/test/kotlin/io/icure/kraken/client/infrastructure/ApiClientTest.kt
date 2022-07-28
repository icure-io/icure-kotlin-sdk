package io.icure.kraken.client.infrastructure

import io.icure.kraken.client.apis.UserApi
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import java.util.*

@ExperimentalCoroutinesApi
@ExperimentalStdlibApi
internal class ApiClientTest {
    @org.junit.jupiter.api.Test
    fun testBadCredentials() = runBlocking {
        try {
            val res = UserApi(
                basePath = "https://kraken.icure.dev",
                authHeader = "Basic ${Base64.getEncoder().encodeToString("testuser:failingpwd".toByteArray(Charsets.UTF_8))}"
            ).getCurrentUser()
            assertNotNull(res)
        } catch(e:Exception) {
            assertEquals(ClientException::class.java, e::class.java)
        }
    }
}
