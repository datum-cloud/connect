package net.datum.connect.share.app

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.google.zxing.client.android.Intents
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import net.datum.connect.share.ShareException
import net.datum.connect.share.TicketInfo
import net.datum.connect.share.parseTicket

/** FragmentActivity, not ComponentActivity: BiometricPrompt needs fragments. */
class MainActivity : FragmentActivity() {
    private val sharedTicket = mutableStateOf<String?>(null)

    private val exportTo = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri -> uri?.let(::writeExport) }

    private val importFrom = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let(::readImport) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sharedTicket.value = ticketFrom(intent)
        setContent {
            Theme {
                Surface(Modifier.fillMaxSize()) {
                    App(
                        sharedTicket = sharedTicket.value,
                        onExport = ::export,
                        onImport = { importFrom.launch(arrayOf("application/json", "text/plain", "application/octet-stream")) },
                    )
                }
            }
        }
    }

    /**
     * Exports after the user proves they can unlock the phone. Unlike a
     * fingerprint-or-nothing check, a phone with no screen lock cannot export:
     * the file holds tickets, which are bearer secrets.
     */
    private fun export() {
        val count = Connections.list.value.size
        if (count == 0) {
            toast("No connections to export")
            return
        }
        val allowed = BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (BiometricManager.from(this).canAuthenticate(allowed) != BiometricManager.BIOMETRIC_SUCCESS) {
            toast("Set a screen lock to export connections")
            return
        }
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    exportTo.launch("datum-connect-connections.json")
                }
            },
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Export connections")
                .setSubtitle("The file contains tickets. Anyone with it can connect while those shares run.")
                .setAllowedAuthenticators(allowed)
                .build(),
        )
    }

    private fun writeExport(uri: Uri) {
        val connections = Connections.list.value
        try {
            contentResolver.openOutputStream(uri, "wt")?.use { it.write(ConnectionsFile.encode(connections).toByteArray()) }
                ?: error("could not open the file")
            toast("Exported ${connections.size} connection${if (connections.size == 1) "" else "s"}")
        } catch (e: Exception) {
            toast("Export failed: ${e.message}")
        }
    }

    private fun readImport(uri: Uri) {
        try {
            val text = contentResolver.openInputStream(uri)?.use { it.readBytes().decodeToString() }
                ?: error("could not open the file")
            val (added, skipped) = Connections.importSaved(ConnectionsFile.decode(text)) { ticket ->
                runCatching { parseTicket(ticket) }.isSuccess
            }
            toast("Imported $added connection${if (added == 1) "" else "s"}" + if (skipped > 0) ", skipped $skipped with invalid tickets" else "")
        } catch (e: Exception) {
            toast("Import failed: ${e.message}")
        }
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        ticketFrom(intent)?.let { sharedTicket.value = it }
    }

    private fun ticketFrom(intent: Intent?): String? =
        intent?.takeIf { it.action == Intent.ACTION_SEND }
            ?.getStringExtra(Intent.EXTRA_TEXT)
            ?.let(::extractTicket)
}

/**
 * Finds a ticket in pasted, scanned, or shared text, such as a full dial command.
 * Accepts DCSHARE2, the prefix before the rename, so older tickets still work.
 */
internal fun extractTicket(text: String): String? =
    Regex("(?:DATUMTUN1|DCSHARE2)[A-Z2-7]+", RegexOption.IGNORE_CASE).find(text)?.value?.uppercase()

private sealed interface Parsed {
    data object Empty : Parsed
    data class Valid(val info: TicketInfo) : Parsed
    data class Invalid(val message: String) : Parsed
}

private fun parse(ticket: String): Parsed {
    if (ticket.isBlank()) return Parsed.Empty
    return try {
        Parsed.Valid(parseTicket(ticket))
    } catch (e: ShareException) {
        Parsed.Invalid(e.message ?: "Not a share ticket")
    }
}

@Composable
private fun App(sharedTicket: String?, onExport: () -> Unit, onImport: () -> Unit) {
    val connections by Connections.list.collectAsStateWithLifecycle()
    var renaming by remember { mutableStateOf<Connection?>(null) }

    LazyColumn(
        Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Column(Modifier.padding(top = 16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                // Drawn in the current text color, so it follows light and dark themes.
                Icon(
                    painter = painterResource(R.drawable.datum_logo),
                    contentDescription = "Datum",
                    modifier = Modifier.padding(bottom = 12.dp).height(24.dp),
                )
                Text("Connect", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "Open services shared from your computers with datumctl connect local. " +
                        "No account needed.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        items(connections, key = { it.id }) { connection ->
            ConnectionCard(connection, onRename = { renaming = connection })
        }
        item {
            AddConnection(sharedTicket, connections)
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onExport) { Text("Export connections") }
                TextButton(onClick = onImport) { Text("Import connections") }
            }
        }
        item {
            Text(
                "Anyone with a ticket can connect until the computer stops sharing. " +
                    "Tickets contain that computer's IP addresses.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(bottom = 16.dp),
            )
        }
    }

    renaming?.let { connection ->
        RenameDialog(connection, onDismiss = { renaming = null })
    }
}

@Composable
private fun ConnectionCard(connection: Connection, onRename: () -> Unit) {
    val context = LocalContext.current
    val status = connection.status
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(connection.name, style = MaterialTheme.typography.titleMedium)
            Text(
                when (status) {
                    Status.Connecting -> "Pairing…"
                    is Status.Ready -> "Open at http://${status.localAddr}"
                    is Status.Failed -> "Could not connect: ${status.message}"
                    Status.Stopped -> "Stopped"
                },
                style = MaterialTheme.typography.bodyMedium,
                color = if (status is Status.Failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
            if (status is Status.Ready && connection.unreachable != null) {
                Text(
                    connection.unreachable.replaceFirstChar(Char::uppercaseChar),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            if (status is Status.Ready) {
                val path = connection.path
                Text(
                    path?.let { p -> p.summary() + (p.remote?.let { "\n$it" } ?: "") }
                        ?: "Path appears once traffic flows",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                connection.traffic?.let { traffic ->
                    Text(
                        traffic.summary() + "\n" + traffic.detail(),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (status is Status.Ready) {
                    Button(onClick = {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("http://${status.localAddr}/")))
                    }) { Text("Open") }
                }
                if (status.active) {
                    OutlinedButton(onClick = { DialService.stop(context, connection.id) }) { Text("Stop") }
                } else {
                    Button(onClick = { DialService.start(context, connection.id) }) { Text("Reconnect") }
                    OutlinedButton(onClick = { Connections.remove(connection.id) }) { Text("Remove") }
                }
                TextButton(onClick = onRename) { Text("Rename") }
            }
        }
    }
}

@Composable
private fun RenameDialog(connection: Connection, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf(connection.name) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Rename connection") },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = {
                    name = it.take(MAX_NAME)
                    error = null
                },
                singleLine = true,
                isError = error != null,
                supportingText = { error?.let { Text(it) } },
            )
        },
        confirmButton = {
            TextButton(onClick = {
                error = Connections.rename(connection.id, name)
                if (error == null) onDismiss()
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun AddConnection(sharedTicket: String?, connections: List<Connection>) {
    val context = LocalContext.current
    var ticket by remember(sharedTicket) { mutableStateOf(sharedTicket.orEmpty()) }
    var name by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("") }
    val parsed = remember(ticket) { parse(ticket.trim()) }
    val sharedPort = (parsed as? Parsed.Valid)?.info?.port?.toInt()
    val chosenPort = port.toIntOrNull()
    val nameProblem = name.trim().takeIf { it.isNotEmpty() }?.let { nameError(it, connections.map(Connection::name)) }
    val portProblem = when {
        port.isEmpty() -> null
        chosenPort == null || chosenPort !in 1..65535 -> "Use a port from 1 to 65535"
        chosenPort in usedPorts(connections) -> "Another connection uses port $chosenPort"
        else -> null
    }

    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { scanned -> extractTicket(scanned)?.let { ticket = it } }
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                if (connections.isEmpty()) "Connect" else "Add another connection",
                style = MaterialTheme.typography.titleMedium,
            )
            OutlinedTextField(
                value = ticket,
                onValueChange = { ticket = extractTicket(it) ?: it },
                label = { Text("Ticket") },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                maxLines = 4,
                isError = parsed is Parsed.Invalid,
                supportingText = {
                    when (parsed) {
                        is Parsed.Valid -> Text("Port ${parsed.info.port} on ${parsed.info.endpointId.take(12)}…")
                        is Parsed.Invalid -> Text(parsed.message)
                        Parsed.Empty -> Text("Scan the QR code or paste the ticket")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = {
                    scanner.launch(
                        ScanOptions()
                            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                            .setPrompt("Scan the QR code from datumctl connect local")
                            .setBeepEnabled(false)
                            // Terminals may draw the code light on dark.
                            .addExtra(Intents.Scan.SCAN_TYPE, Intents.Scan.MIXED_SCAN),
                    )
                }) { Text("Scan QR code") }
                OutlinedButton(onClick = {
                    val clip = context.getSystemService(ClipboardManager::class.java).primaryClip
                    val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)
                    text?.let { extractTicket(it.toString()) }?.let { ticket = it }
                }) { Text("Paste") }
            }
            OutlinedTextField(
                value = name,
                onValueChange = { name = it.take(MAX_NAME) },
                label = { Text("Name (optional)") },
                placeholder = { Text("Name from the computer") },
                singleLine = true,
                isError = nameProblem != null,
                supportingText = nameProblem?.let { { Text(it) } },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = port,
                onValueChange = { value -> port = value.filter(Char::isDigit).take(5) },
                label = { Text("Local port (optional)") },
                placeholder = {
                    Text(sharedPort?.let { defaultPort(it, connections) }?.takeIf { it != 0 }?.toString() ?: "any")
                },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                isError = portProblem != null,
                supportingText = portProblem?.let { { Text(it) } },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                enabled = parsed is Parsed.Valid && nameProblem == null && portProblem == null,
                onClick = {
                    if (Build.VERSION.SDK_INT >= 33) {
                        notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                    }
                    val shared = (parsed as Parsed.Valid).info.port.toInt()
                    val id = Connections.add(
                        ticket = ticket.trim(),
                        port = chosenPort ?: defaultPort(shared, connections),
                        name = name,
                        sharedPort = shared,
                    )
                    DialService.start(context, id)
                    ticket = ""
                    name = ""
                    port = ""
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Connect") }
        }
    }
}

@Composable
private fun Theme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme(),
        content = content,
    )
}
