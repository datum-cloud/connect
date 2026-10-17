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
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import net.datum.connect.share.DialListener
import net.datum.connect.share.DialSession

/**
 * Keeps one dial running while the user switches to a browser. A foreground
 * service is required: without it Android may stop the process and close the
 * local port as soon as this app leaves the screen.
 */
class DialService : Service() {
    private var session: DialSession? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> start(
                ticket = intent.getStringExtra(EXTRA_TICKET).orEmpty(),
                port = intent.getIntExtra(EXTRA_PORT, 0),
            )
            ACTION_STOP -> stop()
        }
        return START_NOT_STICKY
    }

    private fun start(ticket: String, port: Int) {
        stopSession()
        DialStatus.set(DialState.Connecting(port))
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification(getString(R.string.app_name), "Pairing…"),
            if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0,
        )
        try {
            session = DialSession.start(
                ticket,
                port.toUShort(),
                DeviceKey.load(this),
                Build.MODEL,
                Listener(),
            )
        } catch (e: Exception) {
            finish(DialState.Failed(e.message ?: "Could not start"))
        }
    }

    private fun stop() {
        stopSession()
        finish(DialState.Idle)
    }

    private fun stopSession() {
        session?.let {
            it.stop()
            it.close()
        }
        session = null
    }

    private fun finish(state: DialState) {
        DialStatus.set(state)
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopSession()
        super.onDestroy()
    }

    private inner class Listener : DialListener {
        override fun onReady(localAddr: String) {
            DialStatus.set(DialState.Ready(localAddr))
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION_ID, notification("Open at http://$localAddr", "Tap to manage"))
        }

        override fun onStopped(error: String?) {
            // Only report a session that is still current; stop() already
            // handled a user-initiated stop.
            if (error != null) {
                ContextCompat.getMainExecutor(this@DialService).execute {
                    session = null
                    finish(DialState.Failed(error))
                }
            }
        }
    }

    private fun notification(title: String, text: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW)
                    .apply { description = getString(R.string.channel_description) },
            )
        }
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, stopIntent(this), PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_link)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "dial"
        private const val NOTIFICATION_ID = 1
        private const val ACTION_START = "net.datum.connect.share.START"
        private const val ACTION_STOP = "net.datum.connect.share.STOP"
        private const val EXTRA_TICKET = "ticket"
        private const val EXTRA_PORT = "port"

        fun start(context: Context, ticket: String, port: Int) {
            val intent = Intent(context, DialService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_TICKET, ticket)
                .putExtra(EXTRA_PORT, port)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            context.startService(stopIntent(context))
        }

        private fun stopIntent(context: Context) =
            Intent(context, DialService::class.java).setAction(ACTION_STOP)
    }
}
