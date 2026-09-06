package com.tradr.plugin

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import android.util.Base64
import androidx.core.content.ContextCompat
import app.tauri.Logger
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import java.util.UUID

class BleRadio(private val context: Context) {

    companion object {
        const val SERVICE_DATA_LEN: Int = 10
        val TRADR_SERVICE_UUID: UUID = UUID.fromString("00000001-6eed-40d6-85d3-3794eaa7b21c")
        val TRADR_PARCEL_UUID: ParcelUuid = ParcelUuid(TRADR_SERVICE_UUID)
    }

    private var currentAdvertiseCallback: AdvertiseCallback? = null
    private var currentScanCallback: ScanCallback? = null

    private fun makeOutcome(outcome: String, code: Int? = null): JSObject {
        val obj = JSObject()
        obj.put("outcome", outcome)
        if (code != null) {
            obj.put("code", code)
        }
        return obj
    }

    private fun checkAdvertisingPreconditions(adapter: BluetoothAdapter?): JSObject? {
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) {
            return makeOutcome("unsupported")
        }

        val isEnabled = try {
            adapter?.isEnabled == true
        } catch (_: SecurityException) {
            false
        }
        if (adapter == null || !isEnabled) {
            return makeOutcome("adapterUnavailable")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_ADVERTISE) != PackageManager.PERMISSION_GRANTED) {
                return makeOutcome("permissionDenied")
            }
        } else {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_ADMIN) != PackageManager.PERMISSION_GRANTED) {
                return makeOutcome("permissionDenied")
            }
        }

        val advertiser = try {
            adapter.bluetoothLeAdvertiser
        } catch (_: SecurityException) {
            return makeOutcome("permissionDenied")
        }
        if (advertiser == null) {
            return makeOutcome("unsupported")
        }

        return null
    }

    private fun checkScanningPreconditions(adapter: BluetoothAdapter?): JSObject? {
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) {
            return makeOutcome("unsupported")
        }

        val isEnabled = try {
            adapter?.isEnabled == true
        } catch (_: SecurityException) {
            false
        }
        if (adapter == null || !isEnabled) {
            return makeOutcome("adapterUnavailable")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
                return makeOutcome("permissionDenied")
            }
        } else {
            val admin = ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_ADMIN) == PackageManager.PERMISSION_GRANTED
            val loc = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
            if (!admin || !loc) {
                return makeOutcome("permissionDenied")
            }
        }

        return null
    }

    @Synchronized
    fun startAdvertising(serviceDataBytes: ByteArray, invoke: Invoke) {
        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = bluetoothManager?.adapter

        val preconditionOutcome = checkAdvertisingPreconditions(adapter)
        if (preconditionOutcome != null) {
            invoke.resolve(preconditionOutcome)
            return
        }

        val advertiser = adapter?.bluetoothLeAdvertiser
        if (advertiser == null) {
            invoke.resolve(makeOutcome("unsupported"))
            return
        }

        // Replace any in-flight advertisement before starting the new payload.
        currentAdvertiseCallback?.let { prevCallback ->
            try {
                advertiser.stopAdvertising(prevCallback)
            } catch (e: SecurityException) {
                Logger.error("BleRadio: failed to stop previous advertisement", e)
            }
        }
        currentAdvertiseCallback = null

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .setTimeout(0)
            .build()

        // Exclusions are explicit because the 31-byte legacy budget leaves no room for defaults.
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceData(TRADR_PARCEL_UUID, serviceDataBytes)
            .build()

        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                invoke.resolve(makeOutcome("ok"))
            }

            override fun onStartFailure(errorCode: Int) {
                synchronized(this@BleRadio) {
                    if (currentAdvertiseCallback === this) {
                        currentAdvertiseCallback = null
                    }
                }
                invoke.resolve(makeOutcome("advertiseFailed", errorCode))
            }
        }

        currentAdvertiseCallback = callback

        try {
            advertiser.startAdvertising(settings, data, callback)
        } catch (_: SecurityException) {
            currentAdvertiseCallback = null
            invoke.resolve(makeOutcome("permissionDenied"))
        } catch (_: Exception) {
            currentAdvertiseCallback = null
            invoke.resolve(makeOutcome("advertiseFailed", AdvertiseCallback.ADVERTISE_FAILED_INTERNAL_ERROR))
        }
    }

    @Synchronized
    fun stopAdvertising(invoke: Invoke) {
        currentAdvertiseCallback?.let { callback ->
            currentAdvertiseCallback = null
            try {
                val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
                val adapter = bluetoothManager?.adapter
                adapter?.bluetoothLeAdvertiser?.stopAdvertising(callback)
            } catch (e: Exception) {
                Logger.error("BleRadio: failed to stop advertising", e)
            }
        }
        invoke.resolve(makeOutcome("ok"))
    }

    @Synchronized
    fun startScan(channel: Channel, invoke: Invoke) {
        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = bluetoothManager?.adapter

        val preconditionOutcome = checkScanningPreconditions(adapter)
        if (preconditionOutcome != null) {
            invoke.resolve(preconditionOutcome)
            return
        }

        val scanner = adapter?.bluetoothLeScanner
        if (scanner == null) {
            invoke.resolve(makeOutcome("adapterUnavailable"))
            return
        }

        // Replace any in-flight scan before starting a new filter.
        currentScanCallback?.let { prevCallback ->
            try {
                scanner.stopScan(prevCallback)
            } catch (e: SecurityException) {
                Logger.error("BleRadio: failed to stop previous scan", e)
            }
        }
        currentScanCallback = null

        // All-zero mask selects matching UUID while accepting any 10-byte payload content.
        val filter = ScanFilter.Builder()
            .setServiceData(TRADR_PARCEL_UUID, ByteArray(SERVICE_DATA_LEN), ByteArray(SERVICE_DATA_LEN))
            .build()

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setReportDelay(0)
            .build()

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult?) {
                if (result == null) return
                val scanRecord = result.scanRecord ?: return
                val bytes = scanRecord.getServiceData(TRADR_PARCEL_UUID) ?: return
                val device = result.device ?: return
                val address = device.address ?: return
                val encoded = Base64.encodeToString(bytes, Base64.NO_WRAP)
                val push = JSObject()
                push.put("push", "report")
                push.put("handle", address)
                push.put("serviceData", encoded)
                channel.send(push)
            }

            override fun onScanFailed(errorCode: Int) {
                val push = JSObject()
                push.put("push", "failed")
                push.put("code", errorCode)
                channel.send(push)
            }
        }

        currentScanCallback = callback

        try {
            scanner.startScan(listOf(filter), settings, callback)
            invoke.resolve(makeOutcome("ok"))
        } catch (_: SecurityException) {
            currentScanCallback = null
            invoke.resolve(makeOutcome("permissionDenied"))
        } catch (_: Exception) {
            currentScanCallback = null
            invoke.resolve(makeOutcome("adapterUnavailable"))
        }
    }

    @Synchronized
    fun stopScan(invoke: Invoke) {
        currentScanCallback?.let { callback ->
            currentScanCallback = null
            try {
                val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
                val adapter = bluetoothManager?.adapter
                adapter?.bluetoothLeScanner?.stopScan(callback)
            } catch (e: Exception) {
                Logger.error("BleRadio: failed to stop scan", e)
            }
        }
        invoke.resolve(makeOutcome("ok"))
    }
}
