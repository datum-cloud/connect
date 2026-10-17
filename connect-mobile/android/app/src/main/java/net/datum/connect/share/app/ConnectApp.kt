package net.datum.connect.share.app

import android.app.Application
import java.io.File

class ConnectApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // App-private storage, excluded from backups (allowBackup="false").
        Connections.attach(File(filesDir, "connections.json"))
    }
}
