package net.datum.connect.share.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** What the UI and notification show. Owned by [DialService]. */
sealed interface DialState {
    data object Idle : DialState
    data class Connecting(val port: Int) : DialState
    data class Ready(val localAddr: String) : DialState
    data class Failed(val message: String) : DialState
}

object DialStatus {
    private val mutable = MutableStateFlow<DialState>(DialState.Idle)
    val state: StateFlow<DialState> = mutable.asStateFlow()

    internal fun set(state: DialState) {
        mutable.value = state
    }
}
