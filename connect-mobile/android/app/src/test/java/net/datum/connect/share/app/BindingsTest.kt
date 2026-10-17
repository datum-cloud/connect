package net.datum.connect.share.app

import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import net.datum.connect.share.DialListener
import net.datum.connect.share.DialSession
import net.datum.connect.share.PathKind
import net.datum.connect.share.PathReport
import net.datum.connect.share.ShareException
import net.datum.connect.share.deviceEndpointId
import net.datum.connect.share.generateDeviceKey
import net.datum.connect.share.parseTicket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class BindingsTest {
    @Test
    fun deviceKeyHasStableEndpointId() {
        val key = generateDeviceKey()
        assertEquals(32, key.size)
        assertEquals(deviceEndpointId(key), deviceEndpointId(key))
        assertEquals(64, deviceEndpointId(key).length)
    }

    @Test(expected = ShareException.InvalidTicket::class)
    fun rejectsInvalidTicket() {
        parseTicket("DCSHARE2!!")
    }

    @Test
    fun extractsTicketFromDialCommand() {
        assertEquals("DCSHARE2ABC27", extractTicket("datumctl connect dial DCSHARE2ABC27 --bind 9999"))
        assertEquals("DCSHARE2ABC", extractTicket("dcshare2abc"))
        assertNull(extractTicket("no ticket here"))
    }

    /** Pairs with a real `datum-connectd local` and fetches through the tunnel. */
    @Test
    fun dialsRealSharer() {
        val connectd = System.getProperty("connectd.path")
        assumeTrue("set -PconnectdPath to run", connectd != null)

        val origin = ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())
        thread(isDaemon = true) {
            while (true) {
                val client = origin.accept()
                thread(isDaemon = true) {
                    client.use {
                        it.getInputStream().bufferedReader().readLine()
                        it.getOutputStream().write("HTTP/1.0 200 OK\r\n\r\nhello from origin".toByteArray())
                    }
                }
            }
        }
        val sharer = ProcessBuilder(connectd, "local", "127.0.0.1:${origin.localPort}", "--name", "jvm-share")
            .redirectError(File.createTempFile("connectd", ".log"))
            .start()
        try {
            val event = sharer.inputStream.bufferedReader().readLine()
            val ticket = Regex("\"ticket\":\"(DCSHARE2[^\"]+)\"").find(event)!!.groupValues[1]
            assertEquals(origin.localPort, parseTicket(ticket).port.toInt())

            val ready = CountDownLatch(1)
            val stopped = CountDownLatch(1)
            val readyAddr = AtomicReference<String>()
            val readySharer = AtomicReference<String?>()
            val paths = java.util.concurrent.CopyOnWriteArrayList<PathReport>()
            val stopError = AtomicReference<String?>("not stopped")
            val session = DialSession.start(ticket, 0u, generateDeviceKey(), "jvm-test", object : DialListener {
                override fun onReady(localAddr: String, sharerName: String?) {
                    readySharer.set(sharerName)
                    readyAddr.set(localAddr)
                    ready.countDown()
                }

                override fun onPath(path: PathReport) {
                    paths.add(path)
                }

                override fun onStopped(error: String?) {
                    stopError.set(error)
                    stopped.countDown()
                }
            })
            assertTrue("dial ready", ready.await(30, TimeUnit.SECONDS))
            val localAddr = readyAddr.get()
            assertEquals("jvm-share", readySharer.get())
            assertEquals(localAddr, session.localAddr())

            val (host, port) = localAddr.split(":").let { it[0] to it[1].toInt() }
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 5000)
                socket.soTimeout = 10000
                socket.getOutputStream().write("GET / HTTP/1.0\r\n\r\n".toByteArray())
                val body = socket.getInputStream().readBytes().decodeToString()
                assertTrue(body, body.endsWith("hello from origin"))
            }

            // Traffic flowed, so the dialer reports how it reached the sharer.
            val deadline = System.currentTimeMillis() + 10_000
            while (paths.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(50)
            assertTrue("path reported", paths.isNotEmpty())
            assertTrue(paths.last().summary(), paths.last().kind != PathKind.UNKNOWN)

            session.stop()
            assertTrue("dial stopped", stopped.await(10, TimeUnit.SECONDS))
            assertNull(stopError.get())
            session.close()
        } finally {
            sharer.destroy()
            origin.close()
        }
    }
}
