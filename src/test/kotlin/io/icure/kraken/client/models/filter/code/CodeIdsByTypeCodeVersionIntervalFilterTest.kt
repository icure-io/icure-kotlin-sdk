package io.icure.kraken.client.models.filter.code

import io.icure.kraken.client.apis.CodeApi
import io.icure.kraken.client.infrastructure.UsernamePassword
import io.icure.kraken.client.models.filter.chain.FilterChain
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.ExperimentalCoroutinesApi
import utils.CodeBatchGenerator
import utils.removeEntities
import kotlin.random.Random

@OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class)
class CodeIdsByTypeCodeVersionIntervalFilterTest : StringSpec({
    val api = CodeApi(basePath = System.getenv("TEST_ICURE_URL"), authHeader = UsernamePassword(System.getenv("ICURE_USR"), System.getenv("ICURE_PWD")).toBasicAuth())
    val testBatchSize = 40
    val codeGenerator = CodeBatchGenerator()
    val testBatch = codeGenerator.createBatchOfUniqueCodes(testBatchSize).associateBy { it.id }
    val testBatchIds = testBatch.keys.toSortedSet(compareBy { it.lowercase() }).toList()

    beforeSpec {
        testBatch.forEach {
            api.createCode(it.value)
        }
    }

    afterSpec {
        removeEntities(testBatchIds,
            System.getenv("ICURE_COUCHDB_USERNAME"),
            System.getenv("ICURE_COUCHDB_PASSWORD"),
            System.getenv("ICURE_COUCHDB_URL"),
            System.getenv("ICURE_COUCHDB_PREFIX"))
    }

    "If all parameters are null, all the code ids are returned" {
        val filteredResults = api.filterCodesBy(
            null,
            null,
            null,
            null,
            null,
            null,
            FilterChain(CodeIdsByTypeCodeVersionIntervalFilter())
        )
        filteredResults shouldNotBe null
        filteredResults.rows shouldNotBe null
        filteredResults.rows.size shouldBe testBatchSize
        filteredResults.rows.forEach {
            testBatchIds shouldContain it.id
        }
    }

    "If the start ComplexKey is specified only the results that come after it are returned" {
        val startIndex = Random.nextInt(0, testBatchIds.size)
        val startCode = testBatch[testBatchIds[startIndex]]!!
        val filteredResults = api.filterCodesBy(
            null,
            null,
            null,
            null,
            null,
            null,
            FilterChain(CodeIdsByTypeCodeVersionIntervalFilter(
                startType = startCode.type,
                startCode = startCode.code,
                startVersion = startCode.version
            ))
        )
        filteredResults shouldNotBe null
        filteredResults.rows shouldNotBe null
        filteredResults.rows.size shouldBe (testBatchSize-startIndex)
        filteredResults.rows.forEach {
            testBatchIds shouldContain it.id
        }
    }

    "If the end ComplexKey is specified only the results that come before it are returned" {
        val endIndex = Random.nextInt(0, testBatchIds.size)
        val endCode = testBatch[testBatchIds[endIndex]]!!
        val filteredResults = api.filterCodesBy(
            null,
            null,
            null,
            null,
            null,
            null,
            FilterChain(CodeIdsByTypeCodeVersionIntervalFilter(
                endType = endCode.type,
                endCode = endCode.code,
                endVersion = endCode.version
            ))
        )
        filteredResults shouldNotBe null
        filteredResults.rows shouldNotBe null
        filteredResults.rows.size shouldBe (endIndex + 1)
        filteredResults.rows.forEach {
            testBatchIds shouldContain it.id
        }
    }

    "If the start and end ComplexKey are specified only the results that come between them are returned" {
        val startIndex = Random.nextInt(0, testBatchIds.size / 2)
        val startCode = testBatch[testBatchIds[startIndex]]!!
        val endIndex = Random.nextInt(testBatchIds.size / 2, testBatchIds.size)
        val endCode = testBatch[testBatchIds[endIndex]]!!
        val filteredResults = api.filterCodesBy(
            null,
            null,
            null,
            null,
            null,
            null,
            FilterChain(CodeIdsByTypeCodeVersionIntervalFilter(
                startType = startCode.type,
                startCode = startCode.code,
                startVersion = startCode.version,
                endType = endCode.type,
                endCode = endCode.code,
                endVersion = endCode.version
            ))
        )
        filteredResults shouldNotBe null
        filteredResults.rows shouldNotBe null
        filteredResults.rows.size shouldBe (endIndex + 1 - startIndex)
        filteredResults.rows.forEach {
            testBatchIds shouldContain it.id
        }
    }

})