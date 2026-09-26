package com.tradr.plugin

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

class ReceiveService : Service() {

    companion object {
        const val ACTION_STOP = "com.tradr.plugin.ACTION_STOP_RECEIVING"
        private const val NOTIFICATION_ID = 1000
        private const val CHANNEL_ID = "tradr_receive_ready"
        private const val CHANNEL_NAME = "Ready to receive"
    }

    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onCreate() {
        super.onCreate()
        multicastLock = (applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager)
            ?.createMulticastLock("tradr-receive")
            ?.apply {
                setReferenceCounted(false)
            }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            releaseMulticastLock()
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            // Killing the process ensures peers cannot reach the listener after stopping.
            android.os.Process.killProcess(android.os.Process.myPid())
            // Restarting without the Rust listener would show a misleading notification.
            return START_NOT_STICKY
        }

        createNotificationChannelIfNeeded()

        val iconRes = if (applicationInfo.icon != 0) {
            applicationInfo.icon
        } else {
            android.R.drawable.ic_menu_share
        }

        val stopIntent = Intent(this, ReceiveService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingIntentFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val stopPendingIntent = PendingIntent.getService(this, 0, stopIntent, pendingIntentFlags)

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setOngoing(true)
            .setSmallIcon(iconRes)
            .setContentTitle("Tradr")
            .setContentText("Ready to receive")
            .addAction(0, "Stop", stopPendingIntent)
            .build()

        val foregroundServiceType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, foregroundServiceType)

        val lock = multicastLock
        if (lock != null && !lock.isHeld) {
            // Wi-Fi drivers drop multicast packets while the screen is off unless locked.
            lock.acquire()
        }

        // Restarting without the Rust listener would show a misleading notification.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        releaseMulticastLock()
        super.onDestroy()
    }

    private fun releaseMulticastLock() {
        val lock = multicastLock
        if (lock != null && lock.isHeld) {
            lock.release()
        }
    }

    private fun createNotificationChannelIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            if (notificationManager != null && notificationManager.getNotificationChannel(CHANNEL_ID) == null) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    CHANNEL_NAME,
                    NotificationManager.IMPORTANCE_LOW
                )
                notificationManager.createNotificationChannel(channel)
            }
        }
    }
}
