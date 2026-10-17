package net.datum.connect.share.app

import android.content.Context
import java.io.File
import net.datum.connect.share.generateDeviceKey

/**
 * This phone's iroh identity. Kept in app-private, no-backup storage so it
 * never leaves the device, and reused for every dial so a dropped connection
 * can resume against the same sharer without pairing again.
 */
object DeviceKey {
    private const val FILE_NAME = "device.key"

    @Synchronized
    fun load(context: Context): ByteArray {
        val file = File(context.noBackupFilesDir, FILE_NAME)
        if (file.isFile) {
            val bytes = file.readBytes()
            if (bytes.size == 32) return bytes
        }
        val key = generateDeviceKey()
        val tmp = File(context.noBackupFilesDir, "$FILE_NAME.tmp")
        tmp.writeBytes(key)
        if (!tmp.renameTo(file)) {
            tmp.delete()
            error("could not store the device key")
        }
        return key
    }
}
