package io.icure.kraken.client.crypto

data class CryptoConfig<K>(val crypto: Crypto, val marshaller: (K) -> Pair<K, String>, val unmarshaller: (K, String) -> K)
