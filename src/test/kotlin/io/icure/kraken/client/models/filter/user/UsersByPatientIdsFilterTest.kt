package io.icure.kraken.client.models.filter.user

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.SingletonSupport
import io.icure.kraken.client.apis.UserApi
import io.icure.kraken.client.infrastructure.UsernamePassword
import io.icure.kraken.client.models.UserDto
import io.icure.kraken.client.models.filter.chain.FilterChain
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.ExperimentalCoroutinesApi
import utils.removeEntities
import java.util.*

@OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class)
class UsersByPatientIdsFilterTest : StringSpec ({

    val iCureUrl = System.getenv("ICURE_BE_URL") ?: "https://kraken.icure.dev"
    val createdEntitiesId = mutableListOf<String>()

    afterSpec {
        removeEntities(createdEntitiesId,
            System.getenv("ICURE_COUCHDB_USERNAME"),
            System.getenv("ICURE_COUCHDB_PASSWORD"),
            System.getenv("ICURE_COUCHDB_URL"),
            System.getenv("ICURE_COUCHDB_PREFIX"))
    }

    "The UsersByPatientIdsFilter is able to get all the users with a certain PatientId" {
        val api = UserApi(basePath = iCureUrl,
                            authHeader = UsernamePassword(System.getenv("ICURE_USR"), System.getenv("ICURE_PWD")).toBasicAuth())
        val filterPatientId = UUID.randomUUID().toString()
        val user1Uuid = UUID.randomUUID().toString()
        val user1 = api.createUser(UserDto(
            id = user1Uuid,
            login = user1Uuid.substring(0, 8),
            status = UserDto.Status.aCTIVE,
            patientId = filterPatientId
        ))
        user1 shouldNotBe null
        createdEntitiesId.add(user1Uuid)

        val user2Uuid = UUID.randomUUID().toString()
        val user2 = api.createUser(UserDto(
            id = user2Uuid,
            login = user2Uuid.substring(0, 8),
            status = UserDto.Status.aCTIVE,
            patientId = "PATIENT-2"
        ))
        user2 shouldNotBe null
        createdEntitiesId.add(user2Uuid)

        val user3Uuid = UUID.randomUUID().toString()
        val user3 = api.createUser(UserDto(
            id = user3Uuid,
            login = user3Uuid.substring(0, 8),
            status = UserDto.Status.aCTIVE,
            patientId = filterPatientId
        ))
        user3 shouldNotBe null
        createdEntitiesId.add(user3Uuid)

        val filteredResult = api.filterUsersBy(FilterChain(UsersByPatientIdFilter(filterPatientId)), null, null)
        filteredResult shouldNotBe null
        filteredResult.rows shouldNotBe null
        filteredResult.rows.size shouldBe 2
        filteredResult.rows.forEach {
            it.patientId shouldNotBe null
            it.patientId shouldBe filterPatientId
        }
    }

})