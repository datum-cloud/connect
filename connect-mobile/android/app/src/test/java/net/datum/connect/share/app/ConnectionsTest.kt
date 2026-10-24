package net.datum.connect.share.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import net.datum.connect.share.PathKind
import net.datum.connect.share.PathReport
import net.datum.connect.share.TrafficStats

class ConnectionsTest {
    private fun connection(id: Long, port: Int, status: Status) =
        Connection(id, "c$id", false, "DATUMTUN1X", port, status)

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
    fun pathSummaryAndClearing() {
        assertEquals("Direct · 12 ms", PathReport(PathKind.DIRECT, "[2001:db8::1]:1", 12u).summary())
        assertEquals("Relayed", PathReport(PathKind.RELAY, null, null).summary())
        val id = Connections.add("DATUMTUN1P", 0, "path", 9999)
        Connections.setStatus(id, Status.Ready("127.0.0.1:1"))
        Connections.setPath(id, PathReport(PathKind.RELAY, "https://relay.example./", 150u))
        Connections.setStatus(id, Status.Ready("127.0.0.1:1"))
        assertEquals(PathKind.RELAY, Connections.get(id)!!.path?.kind)
        Connections.setStatus(id, Status.Stopped)
        assertEquals(null, Connections.get(id)!!.path)
        Connections.remove(id)
    }

    @Test
    fun unreachableClearsOnForwardOrStop() {
        val id = Connections.add("DATUMTUN1U", 0, "svc", 9999)
        Connections.setStatus(id, Status.Ready("127.0.0.1:1"))
        Connections.setUnreachable(id, "connection refused")
        Connections.setStatus(id, Status.Ready("127.0.0.1:1"))
        assertEquals("connection refused", Connections.get(id)!!.unreachable)
        Connections.setUnreachable(id, null)
        assertEquals(null, Connections.get(id)!!.unreachable)
        Connections.setUnreachable(id, "connection refused")
        Connections.setStatus(id, Status.Stopped)
        assertEquals(null, Connections.get(id)!!.unreachable)
        Connections.remove(id)
    }

    @Test
    fun formatBytesUsesDecimalUnits() {
        assertEquals("0 B", formatBytes(0))
        assertEquals("999 B", formatBytes(999))
        assertEquals("1.0 KB", formatBytes(1000))
        assertEquals("1.5 KB", formatBytes(1536))
        assertEquals("99.9 KB", formatBytes(99_900))
        assertEquals("120 MB", formatBytes(120_000_000))
        assertEquals("1.0 MB", formatBytes(999_999))
        assertEquals("2.5 TB", formatBytes(2_500_000_000_000))
    }

    @Test
    fun meterWorksOutBandwidth() {
        val first = TrafficStats(1_000u, 4_000u, 1u, 1u)
        val start = meter(null, first, 0)
        assertEquals(Traffic(1_000, 4_000, 0, 0, 1), start)
        val later = meter(first, TrafficStats(1_500u, 2_004_000u, 2u, 0u), 2000)
        assertEquals(Traffic(1_500, 2_004_000, 250, 1_000_000, 0), later)
        assertEquals("2.0 MB transferred · 1.0 MB/s", later.summary())
        assertEquals("↓ 2.0 MB · ↑ 1.5 KB", later.detail())
        assertEquals("5.0 KB transferred · 0 B/s", start.summary())
        assertEquals("↓ 4.0 KB · ↑ 1.0 KB · 1 connection open", start.detail())
    }

    @Test
    fun trafficClearsWhenNotReady() {
        val id = Connections.add("DATUMTUN1T", 0, "traffic", 9999)
        Connections.setStatus(id, Status.Ready("127.0.0.1:1"))
        Connections.setTraffic(id, Traffic(1, 2, 3, 4, 1))
        Connections.setStatus(id, Status.Ready("127.0.0.1:1"))
        assertEquals(1L, Connections.get(id)!!.traffic?.sent)
        Connections.setStatus(id, Status.Stopped)
        assertNull(Connections.get(id)!!.traffic)
        Connections.remove(id)
    }

    @Test
    fun sharerNameDoesNotReplaceUserName() {
        val chosen = Connections.add("DATUMTUN1A", 0, "mine", 9999)
        val derived = Connections.add("DATUMTUN1B", 0, null, 9999)
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
