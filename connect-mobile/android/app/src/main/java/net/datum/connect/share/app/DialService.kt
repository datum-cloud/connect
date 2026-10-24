package net.datum.connect.share.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import net.datum.connect.share.DialListener
import net.datum.connect.share.DialSession
import net.datum.connect.share.PathReport
import net.datum.connect.share.TrafficStats

/**
 * Runs one dial per active connection while the user switches to a browser.
 * A foreground service is required: without it Android may stop the process
 * and close the local ports as soon as this app leaves the screen. The service
 * stops itself when no connection is active.
 */
class DialService : Service() {
    private val sessions = mutableMapOf<Long, DialSession>()

    /**
     * Token of the current session for each connection. A callback carries the
     * token its session started with and is dropped if it no longer matches,
     * so a stopped or restarted session cannot change a connection's state.
     * Accessed only on the main thread.
     */
    private val tokens = mutableMapOf<Long, Long>()
    private var nextToken = 1L
    private var foreground = false

    /** Last counter reading per connection, for bandwidth. Main thread only. */
    private val samples = mutableMapOf<Long, Pair<TrafficStats, Long>>()
    private val handler = Handler(Looper.getMainLooper())
    private val sampler = object : Runnable {
        override fun run() {
            sampleTraffic()
            handler.postDelayed(this, SAMPLE_INTERVAL_MS)
        }
    }
    private var sampling = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val id = intent?.getLongExtra(EXTRA_ID, -1) ?: -1
        when (intent?.action) {
            ACTION_START -> {
                // startForegroundService requires startForeground before the
                // service may stop, even if this dial fails at once.
                Connections.get(id)?.let { promote(listOf(it)) }
                start(id)
            }
            ACTION_STOP -> stop(id)
            ACTION_STOP_ALL -> sessions.keys.toList().forEach(::stop)
        }
        updateForeground()
        return START_NOT_STICKY
    }

    private fun start(id: Long) {
        val connection = Connections.get(id) ?: return
        endSession(id)
        val token = nextToken++
        tokens[id] = token
        Connections.setStatus(id, Status.Connecting)
        try {
            sessions[id] = DialSession.start(
                connection.ticket,
                connection.requestedPort.toUShort(),
                DeviceKey.load(this),
                Build.MODEL,
                Listener(id, token),
            )
        } catch (e: Exception) {
            tokens.remove(id)
            Connections.setStatus(id, Status.Failed(e.message ?: "Could not start"))
        }
    }

    private fun stop(id: Long) {
        endSession(id)
        if (Connections.get(id)?.status?.active == true) {
            Connections.setStatus(id, Status.Stopped)
        }
    }

    /** Invalidates callbacks first, then cancels and frees the session. */
    private fun endSession(id: Long) {
        tokens.remove(id)
        samples.remove(id)
        sessions.remove(id)?.let {
            it.stop()
            it.close()
        }
    }

    /**
     * Reads each ready dial's counters and updates its [Traffic]. The list and
     * notification change only when the numbers do, so an idle connection
     * costs one cheap native call a second.
     */
    private fun sampleTraffic() {
        val now = SystemClock.elapsedRealtime()
        var changed = false
        for ((id, session) in sessions) {
            val connection = Connections.get(id) ?: continue
            if (connection.status !is Status.Ready) continue
            val stats = session.traffic()
            val previous = samples.put(id, stats to now)
            val traffic = meter(previous?.first, stats, previous?.let { now - it.second } ?: 0)
            if (traffic != connection.traffic) {
                Connections.setTraffic(id, traffic)
                changed = true
            }
        }
        if (changed) updateForeground()
    }

    private fun updateForeground() {
        val active = Connections.list.value.filter { it.id in sessions }
        if (sessions.isNotEmpty() && !sampling) {
            sampling = true
            handler.postDelayed(sampler, SAMPLE_INTERVAL_MS)
        }
        if (active.isEmpty()) {
            sampling = false
            handler.removeCallbacks(sampler)
            if (foreground) ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            foreground = false
            stopSelf()
            return
        }
        promote(active)
    }

    /** Enters the foreground, or refreshes the notification if already there. */
    private fun promote(active: List<Connection>) {
        val notification = notification(active)
        if (foreground) {
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification)
        } else {
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                notification,
                if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0,
            )
            foreground = true
        }
    }

    override fun onDestroy() {
        handler.removeCallbacks(sampler)
        sessions.keys.toList().forEach(::stop)
        super.onDestroy()
    }

    /** Forwards one session's callbacks to the main thread while it is current. */
    private inner class Listener(private val id: Long, private val token: Long) : DialListener {
        private fun onMain(block: () -> Unit) {
            ContextCompat.getMainExecutor(this@DialService).execute {
                if (tokens[id] == token) {
                    block()
                    updateForeground()
                }
            }
        }

        override fun onPath(path: PathReport) = onMain {
            Connections.setPath(id, path)
        }

        override fun onConnectFailed(reason: String) = onMain {
            Connections.setUnreachable(id, reason)
        }

        override fun onForwarded() = onMain {
            Connections.setUnreachable(id, null)
        }

        override fun onReady(localAddr: String, sharerName: String?) = onMain {
            sharerName?.let { Connections.offerSharerName(id, it) }
            Connections.setStatus(id, Status.Ready(localAddr))
        }

        override fun onStopped(error: String?) = onMain {
            // A current session only stops on its own after an error; stop()
            // invalidates the token before cancelling, so its own stop
            // callback is already dropped.
            endSession(id)
            Connections.setStatus(id, Status.Failed(error ?: "Connection closed"))
        }
    }

    private fun notification(active: List<Connection>): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW)
                    .apply { description = getString(R.string.channel_description) },
            )
        }
        val title = if (active.size == 1) "1 connection open" else "${active.size} connections open"
        val lines = active.map { c ->
            when (val status = c.status) {
                is Status.Ready -> "${c.name}: " + (
                    c.unreachable?.let { "service unreachable" }
                        ?: (
                            "http://${status.localAddr}" +
                                (c.path?.let { " · ${it.summary()}" } ?: "") +
                                (c.traffic?.takeIf { it.rate > 0 }?.let { " · ${formatBytes(it.rate)}/s" } ?: "")
                            )
                    )
                else -> "${c.name}: pairing…"
            }
        }
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stopAll = PendingIntent.getService(
            this, 1,
            Intent(this, DialService::class.java).setAction(ACTION_STOP_ALL),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(lines.joinToString(" · "))
            .setStyle(Notification.BigTextStyle().bigText(lines.joinToString("\n")))
            .setContentIntent(open)
            .setOngoing(true)
            // Updated each second while traffic flows; never sound or buzz again.
            .setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(null, "Stop all", stopAll).build())
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "dial"
        private const val NOTIFICATION_ID = 1
        private const val ACTION_START = "net.datum.connect.share.START"
        private const val ACTION_STOP = "net.datum.connect.share.STOP"
        private const val ACTION_STOP_ALL = "net.datum.connect.share.STOP_ALL"
        private const val EXTRA_ID = "id"
        private const val SAMPLE_INTERVAL_MS = 1000L

        /** Starts (or restarts) the dial for connection [id]. */
        fun start(context: Context, id: Long) {
            val intent = Intent(context, DialService::class.java).setAction(ACTION_START).putExtra(EXTRA_ID, id)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context, id: Long) {
            context.startService(Intent(context, DialService::class.java).setAction(ACTION_STOP).putExtra(EXTRA_ID, id))
        }
    }
}
