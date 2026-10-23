package net.datum.connect.share.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectionsFileTest {
    private fun connection(id: Long, name: String, port: Int, status: Status = Status.Ready("127.0.0.1:$port")) =
        Connection(id, name, nameFromUser = id % 2 == 0L, ticket = "DATUMTUN1T$id", requestedPort = port, status = status)

    @Test
    fun encodeAndDecodeRoundTrip() {
        val text = ConnectionsFile.encode(listOf(connection(1, "api", 3000), connection(2, "docs", 0)))
        assertTrue(text.contains("\"format\": \"datum-connect-connections\""))
        assertFalse("statuses are not saved", text.contains("127.0.0.1"))
        assertEquals(
            listOf(
                ConnectionsFile.Saved("api", false, "DATUMTUN1T1", 3000),
                ConnectionsFile.Saved("docs", true, "DATUMTUN1T2", 0),
            ),
            ConnectionsFile.decode(text),
        )
    }

    @Test
    fun decodeRejectsOtherFiles() {
        assertThrows(IllegalArgumentException::class.java) { ConnectionsFile.decode("{}") }
        assertThrows(IllegalArgumentException::class.java) { ConnectionsFile.decode("not json") }
        assertThrows(IllegalArgumentException::class.java) {
            ConnectionsFile.decode("""{"format":"something-else","version":1,"connections":[]}""")
        }
        assertThrows(IllegalArgumentException::class.java) {
            ConnectionsFile.decode("""{"format":"datum-connect-connections","version":99,"connections":[]}""")
        }
    }

    @Test
    fun savedConnectionsSurviveARestartAsStopped() {
        val dir = createTempDirectory()
        val file = File(dir, "connections.json")
        file.writeText(ConnectionsFile.encode(listOf(connection(7, "api", 3000))))
        // A fresh process attaches once. Connections is a singleton shared by
        // every test in this JVM, so detach afterwards.
        Connections.detach()
        Connections.attach(file)
        try {
            checkAttached(file, dir)
        } finally {
            Connections.detach()
            dir.deleteRecursively()
        }
    }

    private fun checkAttached(file: File, dir: File) {
        val loaded = Connections.list.value.single()
        assertEquals("api", loaded.name)
        assertEquals(3000, loaded.requestedPort)
        assertEquals(Status.Stopped, loaded.status)

        val (added, skipped) = Connections.importSaved(
            listOf(
                ConnectionsFile.Saved("api", true, "DATUMTUN1OK", 4000),
                ConnectionsFile.Saved("bad", true, "nope", 0),
            ),
        ) { it.startsWith("DATUMTUN1") }
        assertEquals(1 to 1, added to skipped)
        assertEquals(listOf("api", "api (2)"), Connections.list.value.map { it.name })

        // Every change is saved; reloading the file gives the same list.
        val saved = ConnectionsFile.decode(file.readText())
        assertEquals(listOf("api", "api (2)"), saved.map { it.name })
        assertFalse(File(dir, "connections.json.tmp").exists())

        Connections.list.value.forEach { Connections.remove(it.id) }
        assertEquals(emptyList<ConnectionsFile.Saved>(), ConnectionsFile.decode(file.readText()))
    }

    private fun createTempDirectory(): File =
        kotlin.io.path.createTempDirectory("connections").toFile()
}
