package com.tradr.plugin

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import androidx.core.content.ContextCompat
import app.tauri.Logger
import app.tauri.plugin.Channel
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import java.util.Arrays
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class BleGattServer(private val context: Context) {

    companion object {
        val SERVICE_UUID: UUID = UUID.fromString("00000002-6eed-40d6-85d3-3794eaa7b21c")
        val C2P_CHAR_UUID: UUID = UUID.fromString("00000003-6eed-40d6-85d3-3794eaa7b21c")
        val P2C_CHAR_UUID: UUID = UUID.fromString("00000004-6eed-40d6-85d3-3794eaa7b21c")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        const val DEFAULT_MTU: Int = 23
    }

    @Volatile
    private var gattServer: BluetoothGattServer? = null
    @Volatile
    private var notifyCharacteristic: BluetoothGattCharacteristic? = null
    @Volatile
    private var pushChannel: Channel? = null
    @Volatile
    private var pendingStartInvoke: Invoke? = null

    private val connectedDevices = ConcurrentHashMap<String, BluetoothDevice>()
    private val deviceMtus = ConcurrentHashMap<String, Int>()

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                connectedDevices[device.address] = device
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                connectedDevices.remove(device.address)
                deviceMtus.remove(device.address)
                pushDisconnected(device.address)
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            deviceMtus[device.address] = mtu
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            connectedDevices[device.address] = device
            if (characteristic.uuid == C2P_CHAR_UUID) {
                if (responseNeeded) {
                    try {
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                    } catch (e: SecurityException) {
                        Logger.error("BleGattServer: sendResponse failed", e)
                    }
                }
                pushBytes(device.address, value ?: byteArrayOf())
            } else {
                if (responseNeeded) {
                    try {
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                    } catch (e: SecurityException) {
                        Logger.error("BleGattServer: sendResponse failed", e)
                    }
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            connectedDevices[device.address] = device
            if (descriptor.uuid == CCCD_UUID && descriptor.characteristic?.uuid == P2C_CHAR_UUID) {
                if (responseNeeded) {
                    try {
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
                    } catch (e: SecurityException) {
                        Logger.error("BleGattServer: sendResponse failed", e)
                    }
                }
                if (value != null && Arrays.equals(value, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)) {
                    pushSubscribed(device.address)
                } else if (value != null && Arrays.equals(value, BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)) {
                    pushUnsubscribed(device.address)
                }
            } else {
                if (responseNeeded) {
                    try {
                        gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                    } catch (e: SecurityException) {
                        Logger.error("BleGattServer: sendResponse failed", e)
                    }
                }
            }
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            val inv = synchronized(this@BleGattServer) {
                val temp = pendingStartInvoke
                pendingStartInvoke = null
                temp
            } ?: return

            if (status == BluetoothGatt.GATT_SUCCESS) {
                inv.resolve(makeOutcome("ok"))
            } else {
                inv.resolve(makeOutcome("serverFailed"))
            }
        }
    }

    private fun makeOutcome(outcome: String): JSObject {
        val obj = JSObject()
        obj.put("outcome", outcome)
        return obj
    }

    private fun pushToChannel(push: JSObject) {
        val channel = pushChannel ?: return
        try {
            channel.send(push)
        } catch (e: Exception) {
            Logger.error("BleGattServer: failed to send push to channel", e)
        }
    }

    private fun pushSubscribed(handle: String) {
        val push = JSObject()
        push.put("push", "subscribed")
        push.put("handle", handle)
        pushToChannel(push)
    }

    private fun pushUnsubscribed(handle: String) {
        val push = JSObject()
        push.put("push", "unsubscribed")
        push.put("handle", handle)
        pushToChannel(push)
    }

    private fun pushDisconnected(handle: String) {
        val push = JSObject()
        push.put("push", "disconnected")
        push.put("handle", handle)
        pushToChannel(push)
    }

    private fun pushBytes(handle: String, value: ByteArray) {
        val encoded = Base64.encodeToString(value, Base64.NO_WRAP)
        val push = JSObject()
        push.put("push", "bytes")
        push.put("handle", handle)
        push.put("data", encoded)
        pushToChannel(push)
    }

    @Synchronized
    fun startServer(channel: Channel, invoke: Invoke) {
        pendingStartInvoke?.resolve(makeOutcome("serverFailed"))
        pendingStartInvoke = null

        for (address in connectedDevices.keys) {
            pushDisconnected(address)
        }
        try {
            gattServer?.close()
        } catch (e: Exception) {
            Logger.error("BleGattServer: failed to close previous server", e)
        }
        gattServer = null
        notifyCharacteristic = null
        pushChannel = null
        connectedDevices.clear()
        deviceMtus.clear()

        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)) {
            invoke.resolve(makeOutcome("unsupported"))
            return
        }

        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val adapter = bluetoothManager?.adapter

        val isEnabled = try {
            adapter?.isEnabled == true
        } catch (_: SecurityException) {
            false
        }
        if (adapter == null || !isEnabled) {
            invoke.resolve(makeOutcome("adapterUnavailable"))
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                invoke.resolve(makeOutcome("permissionDenied"))
                return
            }
        } else {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH) != PackageManager.PERMISSION_GRANTED) {
                invoke.resolve(makeOutcome("permissionDenied"))
                return
            }
        }

        val server = try {
            bluetoothManager.openGattServer(context, gattServerCallback)
        } catch (_: SecurityException) {
            invoke.resolve(makeOutcome("permissionDenied"))
            return
        } catch (e: Exception) {
            Logger.error("BleGattServer: openGattServer failed", e)
            invoke.resolve(makeOutcome("serverFailed"))
            return
        }

        if (server == null) {
            invoke.resolve(makeOutcome("unsupported"))
            return
        }

        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        val c2pChar = BluetoothGattCharacteristic(
            C2P_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        service.addCharacteristic(c2pChar)

        val p2cChar = BluetoothGattCharacteristic(
            P2C_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        val cccd = BluetoothGattDescriptor(
            CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        p2cChar.addDescriptor(cccd)
        service.addCharacteristic(p2cChar)

        val added = try {
            server.addService(service)
        } catch (e: Exception) {
            Logger.error("BleGattServer: addService threw", e)
            false
        }

        if (!added) {
            try {
                server.close()
            } catch (e: Exception) {
                Logger.error("BleGattServer: error closing server", e)
            }
            gattServer = null
            pushChannel = null
            notifyCharacteristic = null
            pendingStartInvoke = null
            invoke.resolve(makeOutcome("serverFailed"))
            return
        }

        gattServer = server
        notifyCharacteristic = p2cChar
        pushChannel = channel
        pendingStartInvoke = invoke
    }

    @Synchronized
    fun stopServer(invoke: Invoke) {
        pendingStartInvoke?.resolve(makeOutcome("serverFailed"))
        pendingStartInvoke = null

        for (address in connectedDevices.keys) {
            pushDisconnected(address)
        }

        try {
            gattServer?.close()
        } catch (e: Exception) {
            Logger.error("BleGattServer: error closing server", e)
        }
        gattServer = null
        notifyCharacteristic = null
        pushChannel = null
        connectedDevices.clear()
        deviceMtus.clear()

        invoke.resolve(makeOutcome("ok"))
    }

    @Synchronized
    fun send(handle: String, bytes: ByteArray, invoke: Invoke) {
        val server = gattServer
        val char = notifyCharacteristic
        if (server == null || char == null) {
            invoke.resolve(makeOutcome("noSuchLink"))
            return
        }

        val device = connectedDevices[handle]
        if (device == null) {
            invoke.resolve(makeOutcome("noSuchLink"))
            return
        }

        val mtu = deviceMtus[handle] ?: DEFAULT_MTU
        val maxPayload = mtu - 3
        if (maxPayload < 1) {
            invoke.resolve(makeOutcome("sendFailed"))
            return
        }

        var offset = 0
        while (offset < bytes.size) {
            val end = Math.min(offset + maxPayload, bytes.size)
            val chunk = bytes.copyOfRange(offset, end)

            val accepted = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    server.notifyCharacteristicChanged(device, char, false, chunk) == BluetoothStatusCodes.SUCCESS
                } else {
                    @Suppress("DEPRECATION")
                    char.value = chunk
                    @Suppress("DEPRECATION")
                    server.notifyCharacteristicChanged(device, char, false)
                }
            } catch (e: Exception) {
                Logger.error("BleGattServer: notification threw", e)
                false
            }

            if (!accepted) {
                invoke.resolve(makeOutcome("sendFailed"))
                return
            }

            offset = end
        }

        invoke.resolve(makeOutcome("ok"))
    }

    @Synchronized
    fun closeLink(handle: String, invoke: Invoke) {
        val device = connectedDevices.remove(handle)
        deviceMtus.remove(handle)

        if (device == null) {
            invoke.resolve(makeOutcome("noSuchLink"))
            return
        }

        try {
            gattServer?.cancelConnection(device)
        } catch (e: Exception) {
            Logger.error("BleGattServer: cancelConnection failed", e)
        }

        invoke.resolve(makeOutcome("ok"))
    }
}
