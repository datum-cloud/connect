package net.datum.connect.share.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/** Longest name accepted here and by connect-share. */
const val MAX_NAME = 64

sealed interface Status {
    data object Connecting : Status
    data class Ready(val localAddr: String) : Status
    data class Failed(val message: String) : Status
    data object Stopped : Status

    val active: Boolean get() = this is Connecting || this is Ready
}

/**
 * One shared service opened on this phone. [requestedPort] is the local port
 * asked for (0 lets the system pick); [Status.Ready] has the bound address.
 */
data class Connection(
    val id: Long,
    val name: String,
    /** True once the user chose the name; the sharer's name no longer replaces it. */
    val nameFromUser: Boolean,
    val ticket: String,
    val requestedPort: Int,
    val status: Status,
)

/** The connections list. Updated by the UI and [DialService] on the main thread. */
object Connections {
    private val mutable = MutableStateFlow<List<Connection>>(emptyList())
    val list: StateFlow<List<Connection>> = mutable.asStateFlow()
    private var nextId = 1L

    /** Adds a connection in [Status.Connecting] and returns its id. */
    fun add(ticket: String, port: Int, name: String?, sharedPort: Int): Long {
        val id = nextId++
        mutable.update { current ->
            val chosen = name?.trim()?.takeIf { it.isNotEmpty() }
            val base = chosen ?: "Port $sharedPort"
            current + Connection(
                id = id,
                name = uniqueName(base, current.map { it.name }),
                nameFromUser = chosen != null,
                ticket = ticket,
                requestedPort = port,
                status = Status.Connecting,
            )
        }
        return id
    }

    fun get(id: Long): Connection? = mutable.value.firstOrNull { it.id == id }

    fun setStatus(id: Long, status: Status) = modify(id) { it.copy(status = status) }

    /** Adopts the sharer's name unless the user already chose one. */
    fun offerSharerName(id: Long, sharerName: String) = mutable.update { current ->
        current.map { c ->
            if (c.id != id || c.nameFromUser) c
            else c.copy(name = uniqueName(sharerName.take(MAX_NAME), current.filter { it.id != id }.map { it.name }))
        }
    }

    /** Renames a connection. Returns an error message, or null on success. */
    fun rename(id: Long, name: String): String? {
        val trimmed = name.trim()
        nameError(trimmed, mutable.value.filter { it.id != id }.map { it.name })?.let { return it }
        modify(id) { it.copy(name = trimmed, nameFromUser = true) }
        return null
    }

    fun remove(id: Long) = mutable.update { current -> current.filter { it.id != id } }

    private fun modify(id: Long, change: (Connection) -> Connection) =
        mutable.update { current -> current.map { if (it.id == id) change(it) else it } }
}

/** Validates a user-chosen name against the other connections' names. */
fun nameError(name: String, others: List<String>): String? = when {
    name.isEmpty() -> "Name can't be empty"
    name.length > MAX_NAME -> "Name can be at most $MAX_NAME characters"
    name.any(Char::isISOControl) -> "Name can't contain control characters"
    others.any { it.equals(name, ignoreCase = true) } -> "Another connection is named \"$name\""
    else -> null
}

/** Returns [base], or "base (2)", "base (3)", … if names already use it. */
fun uniqueName(base: String, names: List<String>): String {
    val taken = names.map { it.lowercase() }.toSet()
    if (base.lowercase() !in taken) return base
    var n = 2
    while ("$base ($n)".lowercase() in taken) n++
    return "$base ($n)"
}

/**
 * Port to request for a new connection: the shared port when an app may bind
 * it and no active connection uses it, otherwise 0 so the system picks.
 */
fun defaultPort(sharedPort: Int, connections: List<Connection>): Int {
    val used = usedPorts(connections)
    return sharedPort.takeIf { it >= 1024 && it !in used } ?: 0
}

/** Ports held or requested by active connections. */
fun usedPorts(connections: List<Connection>): Set<Int> =
    connections.filter { it.status.active }.flatMap { c ->
        listOfNotNull(
            c.requestedPort.takeIf { it != 0 },
            (c.status as? Status.Ready)?.localAddr?.substringAfterLast(':')?.toIntOrNull(),
        )
    }.toSet()
