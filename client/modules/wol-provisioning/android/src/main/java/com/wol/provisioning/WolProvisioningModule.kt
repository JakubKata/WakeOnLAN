package com.wol.provisioning

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Handler
import android.os.Looper
import com.espressif.provisioning.DeviceConnectionEvent
import com.espressif.provisioning.ESPConstants
import com.espressif.provisioning.listeners.ResponseListener
import com.espressif.provisioning.transport.BLETransport
import com.espressif.provisioning.utils.MessengeHelper
import com.wol.provisioning.security.VerifiedSecurity2
import espressif.Constants
import espressif.NetworkConfig
import espressif.NetworkConstants
import espressif.NetworkScan
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.greenrobot.eventbus.EventBus
import org.greenrobot.eventbus.Subscribe
import org.greenrobot.eventbus.ThreadMode
import org.json.JSONObject
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** One authenticated BLE session. All radio state and callbacks are serialized on the main thread. */
@SuppressLint("MissingPermission") // JS obtains runtime permission before starting; denial still throws.
class WolProvisioningModule : Module() {
  private val main = Handler(Looper.getMainLooper())
  private val mutex = Mutex()
  private var operation: Job? = null
  private var transport: BLETransport? = null
  private var peripheral: BluetoothDevice? = null
  private var security: VerifiedSecurity2? = null
  private var connection: CancellableContinuation<Unit>? = null
  private var response: CancellableContinuation<ByteArray>? = null
  private var stopScan: (() -> Unit)? = null
  private val serviceUuid = UUID.fromString("021a9004-0382-4aea-bff4-6b3f1c5adfb4")

  override fun definition() = ModuleDefinition {
    Name("WolProvisioning")

    AsyncFunction("connect") Coroutine { name: String, username: String, password: String ->
      perform(45_000) {
        close()
        require(name.matches(Regex("WOL_[A-Za-z0-9_-]{6,40}")))
        require(username.length in 1..64 && password.length in 16..128)
        val context = appContext.reactContext ?: error("App unavailable")
        val device = findDevice(context, name)
        val link = BLETransport(context)
        transport = link
        peripheral = device
        EventBus.getDefault().register(this@WolProvisioningModule)
        suspendCancellableCoroutine<Unit> { pending ->
          connection = pending
          link.connect(device, serviceUuid)
        }
        val version = JSONObject(link.versionInfo).getJSONObject("prov")
        // Never let advertised metadata select a weaker security implementation.
        require(version.getInt("sec_ver") == 2 && version.getInt("sec_patch_ver") == 1) {
          "Unsupported provisioning security"
        }
        val session = VerifiedSecurity2(username, password, 1)
        var request = session.getNextRequestInSession(null)
        repeat(2) {
          require(request != null) { "Invalid handshake" }
          request = session.getNextRequestInSession(exchange("prov-session", request!!))
        }
        require(request == null) { "Incomplete handshake" }
        security = session
        val info = custom(JSONObject().put("op", "info"))
        val id = info.getString("device_id")
        require(id.matches(Regex("[A-Za-z0-9_-]{16,128}"))) { "Invalid device identity" }
        mapOf("deviceId" to id, "paired" to info.getBoolean("paired"))
      }
    }

    AsyncFunction("scanNetworks") Coroutine { ->
      perform(25_000) {
        scanResponse(MessengeHelper.prepareWiFiScanMsg(), NetworkScan.NetworkScanMsgType.TypeRespScanWifiStart)
        val status = scanResponse(MessengeHelper.prepareGetWiFiScanStatusMsg(), NetworkScan.NetworkScanMsgType.TypeRespScanWifiStatus)
          .respScanWifiStatus
        require(status.scanFinished && status.resultCount in 0..128) { "Invalid network scan" }
        val networks = mutableListOf<Map<String, Any>>()
        for (start in 0 until status.resultCount step 4) {
          val entries = scanResponse(
            MessengeHelper.prepareGetWiFiScanListMsg(start, minOf(4, status.resultCount - start)),
            NetworkScan.NetworkScanMsgType.TypeRespScanWifiResult
          ).respScanWifiResult.entriesList
          for (entry in entries) {
            // WPA2/WPA3 personal networks only; reject open, WEP and enterprise networks.
            if (entry.authValue !in setOf(3, 4, 6, 7) || !entry.ssid.isValidUtf8 || entry.ssid.size() !in 1..32) continue
            networks.add(mapOf("ssid" to entry.ssid.toStringUtf8(), "rssi" to entry.rssi))
          }
        }
        networks.sortedByDescending { it["rssi"] as Int }.distinctBy { it["ssid"] }
      }
    }

    AsyncFunction("configure") Coroutine { ssid: String, password: String, token: String?, unixTime: Double ->
      perform(60_000) {
        require(ssid.toByteArray(Charsets.UTF_8).size in 1..32)
        require(password.toByteArray(Charsets.UTF_8).size in 8..63 || password.matches(Regex("[0-9a-fA-F]{64}")))
        require(unixTime.isFinite() && unixTime >= 1_767_225_600 && unixTime < 4_102_444_800)
        val command = JSONObject().put("time", unixTime.toLong())
        if (token != null) {
          require(token.matches(Regex("[A-Za-z0-9_-]{16,128}")))
          command.put("op", "claim").put("token", token)
        } else {
          command.put("op", "configure")
        }
        require(custom(command).getBoolean("ok")) { "Device rejected configuration" }
        val set = NetworkConfig.NetworkConfigPayload.parseFrom(
          encrypted("prov-config", MessengeHelper.prepareWiFiConfigMsg(ssid, password)))
        require(set.msg == NetworkConfig.NetworkConfigMsgType.TypeRespSetWifiConfig && set.hasRespSetWifiConfig() &&
          set.respSetWifiConfig.status == Constants.Status.Success) { "Wi-Fi configuration rejected" }
        val apply = NetworkConfig.NetworkConfigPayload.parseFrom(
          encrypted("prov-config", MessengeHelper.prepareApplyWiFiConfigMsg()))
        require(apply.msg == NetworkConfig.NetworkConfigMsgType.TypeRespApplyWifiConfig && apply.hasRespApplyWifiConfig() &&
          apply.respApplyWifiConfig.status == Constants.Status.Success) { "Wi-Fi configuration rejected" }
        // Applying settings only starts association. Confirm the requested network before
        // accepting a cloud-online result, which may still describe the previous connection.
        while (true) {
          delay(1_000)
          val result = NetworkConfig.NetworkConfigPayload.parseFrom(
            encrypted("prov-config", MessengeHelper.prepareGetWiFiConfigStatusMsg()))
          require(result.msg == NetworkConfig.NetworkConfigMsgType.TypeRespGetWifiStatus && result.hasRespGetWifiStatus())
          val status = result.respGetWifiStatus
          require(status.status == Constants.Status.Success) { "Wi-Fi status failed" }
          when (status.wifiStaState) {
            NetworkConstants.WifiStationState.Connected -> {
              require(status.hasWifiConnected() && status.wifiConnected.ssid.toStringUtf8() == ssid) {
                "Device joined a different network"
              }
              break
            }
            NetworkConstants.WifiStationState.ConnectionFailed -> error("Wi-Fi connection failed")
            NetworkConstants.WifiStationState.Disconnected, NetworkConstants.WifiStationState.Connecting -> Unit
            else -> error("Invalid Wi-Fi state")
          }
        }
        // Cloud account/device verification remains the final success condition.
      }
    }

    AsyncFunction("cancel") Coroutine { ->
      withContext(Dispatchers.Main.immediate) {
        operation?.cancel()
        close()
      }
    }
    OnDestroy { main.post { operation?.cancel(); close() } }
  }

  private suspend fun <T> perform(timeout: Long, body: suspend () -> T): T = withContext(Dispatchers.Main.immediate) {
    mutex.withLock {
      operation = currentCoroutineContext()[Job]
      try {
        withTimeout(timeout) { body() }
      } catch (error: CancellationException) {
        close()
        throw error
      } catch (error: Exception) {
        close()
        // Do not expose SDK exception content (which can include external data) to JavaScript/logging.
        throw IllegalStateException("Secure device setup failed", null)
      } finally {
        operation = null
      }
    }
  }

  private suspend fun findDevice(context: Context, name: String): BluetoothDevice = withTimeout(15_000) {
    val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
    require(adapter != null && adapter.isEnabled) { "Bluetooth is unavailable" }
    val scanner = adapter.bluetoothLeScanner ?: error("Bluetooth scan unavailable")
    try {
      suspendCancellableCoroutine { pending ->
        val callback = object : ScanCallback() {
          override fun onScanResult(callbackType: Int, result: ScanResult) {
            main.post {
              if (pending.isActive && result.scanRecord?.deviceName == name) pending.resume(result.device)
            }
          }
          override fun onScanFailed(errorCode: Int) {
            main.post { if (pending.isActive) pending.resumeWithException(IllegalStateException("BLE scan failed")) }
          }
        }
        stopScan = { scanner.stopScan(callback) }
        scanner.startScan(listOf(ScanFilter.Builder().setDeviceName(name).build()),
          ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(), callback)
      }
    } finally {
      val finish = stopScan
      stopScan = null
      runCatching { finish?.invoke() }
    }
  }

  @Subscribe(threadMode = ThreadMode.MAIN)
  fun onDeviceEvent(event: DeviceConnectionEvent) {
    if (event.eventType == ESPConstants.EVENT_DEVICE_CONNECTED) {
      // The SDK's global events have no source. Ignore a previous link's late event.
      if (transport?.versionInfo == null) return
      connection?.let { if (it.isActive) it.resume(Unit) }
      connection = null
    } else {
      val device = peripheral
      val context = appContext.reactContext
      if (device != null && context != null) {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val state = runCatching { manager.getConnectionState(device, BluetoothProfile.GATT) }.getOrNull()
        if (state == BluetoothProfile.STATE_CONNECTED || state == BluetoothProfile.STATE_CONNECTING) return
      }
      val error = IllegalStateException("Device disconnected")
      connection?.let { if (it.isActive) it.resumeWithException(error) }
      response?.let { if (it.isActive) it.resumeWithException(error) }
      connection = null
      response = null
      security = null
    }
  }

  private suspend fun exchange(path: String, bytes: ByteArray): ByteArray = withTimeout(12_000) {
    val link = transport ?: error("Device disconnected")
    suspendCancellableCoroutine { pending ->
      response = pending
      link.sendConfigData(path, bytes, object : ResponseListener {
        override fun onSuccess(data: ByteArray?) {
          main.post {
            if (response === pending) response = null
            if (pending.isActive) {
              if (data == null || data.size > 8192) pending.resumeWithException(IllegalStateException("Invalid BLE response"))
              else pending.resume(data)
            }
          }
        }
        override fun onFailure(error: Exception) {
          main.post {
            if (response === pending) response = null
            if (pending.isActive) pending.resumeWithException(IllegalStateException("BLE request failed"))
          }
        }
      })
    }
  }

  private suspend fun encrypted(path: String, bytes: ByteArray): ByteArray {
    val session = security ?: error("No authenticated session")
    return session.decrypt(exchange(path, session.encrypt(bytes)))
  }

  private suspend fun custom(value: JSONObject): JSONObject = JSONObject(
    String(encrypted("wol-claim", value.toString().toByteArray(Charsets.UTF_8)), Charsets.UTF_8))

  private suspend fun scanResponse(bytes: ByteArray, kind: NetworkScan.NetworkScanMsgType): NetworkScan.NetworkScanPayload {
    val result = NetworkScan.NetworkScanPayload.parseFrom(encrypted("prov-scan", bytes))
    require(result.msg == kind && result.status == Constants.Status.Success) { "Invalid scan response" }
    return result
  }

  private fun close() {
    if (EventBus.getDefault().isRegistered(this)) EventBus.getDefault().unregister(this)
    val finishScan = stopScan
    val link = transport
    stopScan = null
    transport = null
    peripheral = null
    security = null
    connection?.cancel()
    response?.cancel()
    connection = null
    response = null
    // Android may revoke permissions while the screen is backgrounded.
    runCatching { finishScan?.invoke() }
    runCatching { link?.disconnect() }
  }
}
