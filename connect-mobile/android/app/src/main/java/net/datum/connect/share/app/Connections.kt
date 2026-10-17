package net.datum.connect.share.app

import java.io.File
import net.datum.connect.share.PathKind
import net.datum.connect.share.PathReport
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
    /** The live path to the sharer while ready; never saved. */
    val path: PathReport? = null,
)

/**
 * The connections list. Updated by the UI and [DialService] on the main thread.
 * Names, tickets, and ports are saved to app-private storage after every
 * change, so they survive restarts and updates; statuses are not saved.
 */
object Connections {
    private val mutable = MutableStateFlow<List<Connection>>(emptyList())
    val list: StateFlow<List<Connection>> = mutable.asStateFlow()
    private var nextId = 1L
    private var file: File? = null

    /**
     * Loads the saved list from [file] and saves every later change there.
     * Saved connections come back stopped: their sharers may have restarted.
     */
    @Synchronized
    fun attach(file: File) {
        if (this.file != null) return
        this.file = file
        val saved = try {
            file.takeIf(File::isFile)?.readText()?.let(ConnectionsFile::decode).orEmpty()
        } catch (e: IllegalArgumentException) {
            emptyList()
        }
        mutable.value = saved.mapIndexed { index, s ->
            Connection(index + 1L, s.name, s.nameFromUser, s.ticket, s.port, Status.Stopped)
        }
        nextId = saved.size + 1L
    }

    /** Stops saving and clears the list. Tests only; the app attaches once. */
    @Synchronized
    internal fun detach() {
        file = null
        mutable.value = emptyList()
        nextId = 1L
    }

    /**
     * Writes the list atomically: a crash mid-write leaves the old copy. A
     * failed write (for example a full disk) keeps the in-memory list and
     * retries on the next change rather than crashing the app.
     */
    private fun persist() {
        val target = file ?: return
        val tmp = File(target.parentFile, target.name + ".tmp")
        try {
            tmp.writeText(ConnectionsFile.encode(mutable.value))
            if (!tmp.renameTo(target)) tmp.delete()
        } catch (e: java.io.IOException) {
            tmp.delete()
        }
    }

    /**
     * Adds imported connections, stopped, with names made unique. Entries whose
     * ticket fails [validTicket] are skipped. Returns (added, skipped).
     */
    fun importSaved(saved: List<ConnectionsFile.Saved>, validTicket: (String) -> Boolean): Pair<Int, Int> {
        var added = 0
        mutable.update { current ->
            val names = current.map { it.name }.toMutableList()
            val incoming = saved.filter { validTicket(it.ticket) }.map { s ->
                val name = uniqueName(s.name.trim().take(MAX_NAME).ifEmpty { "Imported" }, names)
                names += name
                Connection(nextId++, name, s.nameFromUser, s.ticket, s.port.coerceIn(0, 65535), Status.Stopped)
            }
            added = incoming.size
            current + incoming
        }
        persist()
        return added to (saved.size - added)
    }

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
        persist()
        return id
    }

    fun get(id: Long): Connection? = mutable.value.firstOrNull { it.id == id }

    /** A new status clears the path unless the connection stays ready. */
    fun setStatus(id: Long, status: Status) =
        modify(id) { it.copy(status = status, path = if (status is Status.Ready) it.path else null) }

    fun setPath(id: Long, path: PathReport) = modify(id) { it.copy(path = path) }

    /** Adopts the sharer's name unless the user already chose one. */
    fun offerSharerName(id: Long, sharerName: String) {
        mutable.update { current ->
            current.map { c ->
                if (c.id != id || c.nameFromUser) c
                else c.copy(name = uniqueName(sharerName.take(MAX_NAME), current.filter { it.id != id }.map { it.name }))
            }
        }
        persist()
    }

    /** Renames a connection. Returns an error message, or null on success. */
    fun rename(id: Long, name: String): String? {
        val trimmed = name.trim()
        nameError(trimmed, mutable.value.filter { it.id != id }.map { it.name })?.let { return it }
        modify(id) { it.copy(name = trimmed, nameFromUser = true) }
        persist()
        return null
    }

    fun remove(id: Long) {
        mutable.update { current -> current.filter { it.id != id } }
        persist()
    }

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

/** For display: "Direct · 12 ms", "Relayed · 150 ms", or "Path unknown". */
fun PathReport.summary(): String {
    val kind = when (kind) {
        PathKind.DIRECT -> "Direct"
        PathKind.RELAY -> "Relayed"
        PathKind.UNKNOWN -> "Path unknown"
    }
    return rttMs?.let { "$kind · $it ms" } ?: kind
}
