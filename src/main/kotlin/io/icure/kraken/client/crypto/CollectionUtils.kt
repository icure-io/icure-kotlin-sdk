package io.icure.kraken.client.crypto


/**
 * Returns the first result of applying the given [transform] function
 * to each element in the original collection that is not null.
 */
inline fun <T, R> Iterable<T>.mapFirstNotNull(transform: (T) -> R): R? {
    for (item in this) transform(item)?.let { return it }
    return null
}
