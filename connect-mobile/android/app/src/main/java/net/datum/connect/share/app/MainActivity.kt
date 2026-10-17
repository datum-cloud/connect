package net.datum.connect.share.app

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
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

class MainActivity : ComponentActivity() {
    private val sharedTicket = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sharedTicket.value = ticketFrom(intent)
        setContent {
            Theme {
                Surface(Modifier.fillMaxSize()) {
                    App(initialTicket = sharedTicket.value)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        ticketFrom(intent)?.let { sharedTicket.value = it }
    }

    private fun ticketFrom(intent: Intent?): String? =
        intent?.takeIf { it.action == Intent.ACTION_SEND }
            ?.getStringExtra(Intent.EXTRA_TEXT)
            ?.let(::extractTicket)
}

/** Finds a ticket in pasted, scanned, or shared text, such as a full dial command. */
internal fun extractTicket(text: String): String? =
    Regex("DCSHARE2[A-Z2-7]+", RegexOption.IGNORE_CASE).find(text)?.value?.uppercase()

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
private fun App(initialTicket: String?) {
    val context = LocalContext.current
    val state by DialStatus.state.collectAsStateWithLifecycle()
    var ticket by remember(initialTicket) { mutableStateOf(initialTicket.orEmpty()) }
    var port by remember { mutableStateOf("") }
    val parsed = remember(ticket) { parse(ticket.trim()) }

    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { scanned -> extractTicket(scanned)?.let { ticket = it } }
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Datum Connect", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Open a service shared from your computer with datumctl connect local. " +
                "No account needed.",
            style = MaterialTheme.typography.bodyMedium,
        )

        when (val current = state) {
            is DialState.Connecting -> StatusCard("Pairing…", "Reaching the computer that shared this ticket.") {
                OutlinedButton(onClick = { DialService.stop(context) }) { Text("Cancel") }
            }
            is DialState.Ready -> StatusCard("Connected", "Open http://${current.localAddr} in any app on this phone.") {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("http://${current.localAddr}/")))
                    }) { Text("Open in browser") }
                    OutlinedButton(onClick = { DialService.stop(context) }) { Text("Stop") }
                }
            }
            DialState.Idle, is DialState.Failed -> {
                if (current is DialState.Failed) {
                    StatusCard("Could not connect", current.message) {}
                }
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
                    value = port,
                    onValueChange = { value -> port = value.filter(Char::isDigit).take(5) },
                    label = { Text("Local port (optional)") },
                    placeholder = {
                        Text((parsed as? Parsed.Valid)?.info?.port?.let(::defaultPort)?.toString() ?: "any")
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    enabled = parsed is Parsed.Valid,
                    onClick = {
                        if (Build.VERSION.SDK_INT >= 33) {
                            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                        }
                        val info = (parsed as Parsed.Valid).info
                        val chosen = port.toIntOrNull()?.takeIf { it in 1..65535 } ?: defaultPort(info.port)
                        DialService.start(context, ticket.trim(), chosen)
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Connect") }
                Text(
                    "Anyone with a ticket can connect until the computer stops sharing. " +
                        "Tickets contain that computer's IP addresses.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

/** Use the shared port when an app may bind it; otherwise let the system pick. */
private fun defaultPort(sharedPort: UShort): Int =
    sharedPort.toInt().takeIf { it >= 1024 } ?: 0

@Composable
private fun StatusCard(title: String, body: String, actions: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(body, style = MaterialTheme.typography.bodyMedium)
            actions()
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
