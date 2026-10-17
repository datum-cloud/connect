package net.datum.connect.share.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class ConnectionsTest {
    private fun connection(id: Long, port: Int, status: Status) =
        Connection(id, "c$id", false, "DCSHARE2X", port, status)

    @Test
    fun uniqueNameAddsSuffix() {
        assertEquals("api", uniqueName("api", listOf("web")))
        assertEquals("api (2)", uniqueName("api", listOf("API")))
        assertEquals("api (3)", uniqueName("api", listOf("api", "api (2)")))
    }

    @Test
    fun nameErrorRejectsDuplicatesAndBadNames() {
        assertNull(nameError("api", listOf("web")))
        assertNotNull(nameError("", emptyList()))
        assertNotNull(nameError("x".repeat(MAX_NAME + 1), emptyList()))
        assertNotNull(nameError("a\u001b[31m", emptyList()))
        assertEquals("Another connection is named \"Api\"", nameError("Api", listOf("api")))
    }

    @Test
    fun defaultPortAvoidsActiveConnections() {
        val active = listOf(
            connection(1, 9999, Status.Connecting),
            connection(2, 0, Status.Ready("127.0.0.1:40000")),
            connection(3, 8080, Status.Stopped),
        )
        assertEquals(setOf(9999, 40000), usedPorts(active))
        assertEquals(0, defaultPort(9999, active))
        assertEquals(8080, defaultPort(8080, active))
        assertEquals(0, defaultPort(80, emptyList()))
    }

    @Test
    fun sharerNameDoesNotReplaceUserName() {
        val chosen = Connections.add("DCSHARE2A", 0, "mine", 9999)
        val derived = Connections.add("DCSHARE2B", 0, null, 9999)
        Connections.offerSharerName(chosen, "laptop:9999")
        Connections.offerSharerName(derived, "laptop:9999")
        assertEquals("mine", Connections.get(chosen)!!.name)
        assertEquals("laptop:9999", Connections.get(derived)!!.name)
        assertNull(Connections.rename(chosen, "renamed"))
        assertNotNull(Connections.rename(derived, "RENAMED"))
        Connections.remove(chosen)
        Connections.remove(derived)
    }
}
