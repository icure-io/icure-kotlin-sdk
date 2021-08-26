package io.icure.kraken.client.crypto
data class CryptoConfig<K>(val crypto: Crypto, val marshaller: (K) -> Pair<K, ByteArray>, val unmarshaller: (K, ByteArray) -> K)
