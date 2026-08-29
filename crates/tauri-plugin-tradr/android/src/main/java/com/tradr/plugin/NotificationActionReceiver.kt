package com.tradr.plugin

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationManagerCompat

// Handles Accept and Decline action button clicks from incoming transfer notifications.
class NotificationActionReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val notificationId = intent.getIntExtra(EXTRA_NOTIFICATION_ID, -1)
        val transferId = intent.getStringExtra(EXTRA_TRANSFER_ID)

        if (notificationId != -1) {
            val notificationManager = NotificationManagerCompat.from(context)
            notificationManager.cancel(notificationId)
        }

        TradrPlugin.onNotificationAction(action, transferId)
    }
}
