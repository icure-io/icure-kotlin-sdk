package io.icure.kraken.client.apis

import kotlin.reflect.KProperty1
import kotlin.reflect.full.memberProperties

fun <K : Any> K.differences(o: K?): List<Diff> {
    val self: K = this
    return o?.let { other ->
        if (self is List<*>) {
            (this as List<*>).mapIndexedNotNull { idx, v ->
                when {
                    idx>(other as List<*>).size -> {
                        Diff("${idx} <-> missing", listOf())
                    }
                    v != other[idx] -> {
                        Diff("${idx} <-> ${idx}", v?.differences(other[idx]) ?: listOf())
                    }
                    else -> {
                        null
                    }
                }
            } + if ((other as List<*>).size>(this as List<*>).size) other.takeLast(other.size - this.size).mapIndexed { idx, _ ->
                Diff("missing <-> ${idx+this.size}", listOf())
            } else listOf()
        } else if (self is Set<*>) {
            val notInSelf = (other as Set<*>) - self
            val notInOther = self - (other as Set<*>)

            val othersTreated = mutableSetOf<Any>()

            notInSelf.map { s -> Diff("<-", notInOther.map { o -> o to (s?.differences(o) ?: listOf()) }.minByOrNull { it.second.size }?.let {
                it.first?.let { it1 -> othersTreated.add(it1) }
                it.second.toList()
            } ?: listOf()) }.toList() +
                    (notInOther - othersTreated).map { o -> Diff("->", notInSelf.map { s -> s?.differences(o) ?: listOf() }.minByOrNull { it.size }?.toList()
                        ?: listOf()) }.toList()
        } else if (self is ByteArray) {
            when {
                other !is ByteArray -> {
                    listOf(Diff("self"))
                }
                self.size != other.size -> {
                    listOf(Diff("self"))
                }
                self.withIndex().any { iv -> iv.value != other[iv.index] } ->  self.withIndex().filter { iv -> iv.value != other[iv.index] }.map{ iv ->
                    Diff(iv.index.toString())
                }
                else -> listOf()
            }
        } else {
            val props: Collection<KProperty1<Any, *>> = try { (this::class).memberProperties as Collection<KProperty1<Any, *>> } catch (e:Exception) { listOf() }
            props.filter {
                try {
                    val selfValue = it.get(self)
                    val otherValue = it.get(other)
                    selfValue != otherValue
                } catch (e: Exception) {
                    false
                }
            }.map { kp ->
                Diff(kp.name, kp.get(self)?.let { s -> (s as Any?)?.differences((kp.get(other))) } ?: listOf())
            }
        }
    } ?: listOf()
}

data class Diff(val propertyName: String, val diffs: List<Diff> = listOf()) {
    fun toString(prefix: String = ""): String {
        return "$prefix$propertyName, diffs=\n${diffs.joinToString("\n") { prefix + it.toString("  $prefix") }})"
    }
}
