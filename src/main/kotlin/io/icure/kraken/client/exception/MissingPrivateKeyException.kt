package io.icure.kraken.client.exception

class MissingPrivateKeyException(val dataOwnerId: String, reason: String) : IllegalArgumentException(reason)
