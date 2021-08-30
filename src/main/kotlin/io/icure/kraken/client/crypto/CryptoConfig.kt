package io.icure.kraken.client.crypto
data class CryptoConfig<K>(val crypto: Crypto, val marshaller: suspend (K) -> Pair<K, ByteArray>, val unmarshaller: suspend (K, ByteArray) -> K)
