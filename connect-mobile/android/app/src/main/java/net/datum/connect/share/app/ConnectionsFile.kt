package net.datum.connect.share.app

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The saved form of the connection list, used both for the app's private
 * copy and for exports. It holds names, tickets, and ports; never the device
 * key, so an imported list pairs as a new device.
 */
object ConnectionsFile {
    const val FORMAT = "datum-connect-connections"
    const val VERSION = 1

    @Serializable
    data class Saved(
        val name: String,
        @SerialName("nameFromUser") val nameFromUser: Boolean = true,
        val ticket: String,
        val port: Int = 0,
    )

    @Serializable
    private data class Document(
        val format: String,
        val version: Int,
        val connections: List<Saved>,
    )

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
        encodeDefaults = true
    }

    fun encode(connections: List<Connection>): String = json.encodeToString(
        Document.serializer(),
        Document(
            format = FORMAT,
            version = VERSION,
            connections = connections.map { Saved(it.name, it.nameFromUser, it.ticket, it.requestedPort) },
        ),
    )

    /** Parses a saved or exported list. Throws [IllegalArgumentException] if it isn't one. */
    fun decode(text: String): List<Saved> {
        val document = try {
            json.decodeFromString(Document.serializer(), text)
        } catch (e: kotlinx.serialization.SerializationException) {
            throw IllegalArgumentException("Not a Datum Connect connections file", e)
        }
        require(document.format == FORMAT) { "Not a Datum Connect connections file" }
        require(document.version <= VERSION) { "This file needs a newer version of the app" }
        return document.connections
    }
}
