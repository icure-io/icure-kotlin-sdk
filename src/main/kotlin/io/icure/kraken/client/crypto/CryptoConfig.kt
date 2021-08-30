package io.icure.kraken.client.crypto
/*
D is the decrypted class, K is the crypted class
 */
data class CryptoConfig<D,K>(
    val crypto: Crypto,
    /* The marshaller maps an instance of the decrypted class to a curated (where all sensitive fields have been set to null) instance of the crypted class
    + a ByteArray that holds the serialized information necessary to reconstruct the sensitive fields
     */
    val marshaller: suspend (D) -> Pair<K, ByteArray>,
    /* The unmarshaller maps an instance of the crypted class to an instance of the decrypted class
    + it is responsible for deserializing the ByteArray and to reinject the sensitive fields inside the decrypted instance
     */
    val unmarshaller: suspend (K, ByteArray) -> D
)
