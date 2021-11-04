@file:Suppress("unused")
package io.icure.kraken.client.infrastructure

import java.lang.RuntimeException

class ClientException(message: String? = null, val statusCode: Int = -1, val response: Response? = null, val details: ErrorDetails) : RuntimeException(message)
class ServerException(message: String? = null, val statusCode: Int = -1, val response: Response? = null, val details: ErrorDetails) : RuntimeException(message)
data class ErrorDetails(val timestamp: Long, val error: String? = null, val message: String?, val requestId: String? = null, val status: Int, val path: String? = null)
