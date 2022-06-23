package io.icure.kraken.client.extendedapis.infrastructure

import io.icure.kraken.client.apis.DeviceApi
import io.icure.kraken.client.apis.HealthcarePartyApi
import io.icure.kraken.client.apis.PatientApi
import io.icure.kraken.client.crypto.LocalCrypto
import io.icure.kraken.client.crypto.toPublicKey
import io.icure.kraken.client.extendedapis.DataOwner
import io.icure.kraken.client.extendedapis.DataOwnerResolver
import io.icure.kraken.client.extendedapis.dataOwnerId
import io.icure.kraken.client.models.UserDto
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import java.security.interfaces.RSAPrivateKey

@FlowPreview
@ExperimentalStdlibApi
@ExperimentalCoroutinesApi
object ExtendedTestUtils {

    fun localCrypto(basePath: String,
                    authHeader: String,
                    privKey: RSAPrivateKey,
                    user: UserDto,
                    dataOwner: DataOwner
    ) : LocalCrypto {
        return LocalCrypto(
            dataOwnerWrapperFor(basePath, authHeader), mapOf(
                user.dataOwnerId() to listOf(privKey to dataOwner.publicKey!!.toPublicKey())
            )
        )
    }

    fun dataOwnerWrapperFor(basePath: String, authHeader: String) : DataOwnerResolver {
        val hcPartyApi = HealthcarePartyApi(basePath = basePath, authHeader = authHeader)
        val patientApi = PatientApi(basePath = basePath, authHeader = authHeader)
        val deviceApi = DeviceApi(basePath = basePath, authHeader = authHeader)

        return DataOwnerResolver(hcPartyApi, patientApi, deviceApi)
    }
}