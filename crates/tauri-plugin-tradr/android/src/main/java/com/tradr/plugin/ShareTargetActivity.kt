package com.tradr.plugin

import android.app.Activity
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "ShareTargetActivity"
private const val LARGE_FILE_THRESHOLD_BYTES = 50L * 1024L * 1024L
const val EXTRA_SHARED_FILES_JSON = "com.tradr.plugin.EXTRA_SHARED_FILES_JSON"
const val ACTION_SHARED_FILES = "com.tradr.plugin.ACTION_SHARED_FILES"
const val EXTRA_TARGET_DEVICE = "com.tradr.plugin.EXTRA_TARGET_DEVICE"

data class SharedFileEntry(
    val name: String,
    val size: Long,
    val cachePath: String?,
    val fd: Int?
) {
    fun toJson(): JSONObject {
        val obj = JSONObject()
        obj.put("name", name)
        obj.put("size", size)
        if (cachePath != null) {
            obj.put("cachePath", cachePath)
        } else {
            obj.put("cachePath", JSONObject.NULL)
        }
        if (fd != null) {
            obj.put("fd", fd)
        } else {
            obj.put("fd", JSONObject.NULL)
        }
        return obj
    }
}

object ShareIntentProcessor {
    fun processIntent(
        context: Context,
        contentResolver: ContentResolver,
        cacheDir: File,
        intent: Intent
    ): List<SharedFileEntry> {
        val uris = extractStreamUris(intent)
        val results = mutableListOf<SharedFileEntry>()
        for (uri in uris) {
            val entry = processUri(context, contentResolver, cacheDir, uri)
            if (entry != null) {
                results.add(entry)
            }
        }
        return results
    }

    fun extractStreamUris(intent: Intent): List<Uri> {
        val result = mutableListOf<Uri>()
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri: Uri? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                }
                if (uri != null) {
                    result.add(uri)
                } else if (intent.clipData != null && intent.clipData!!.itemCount > 0) {
                    val clipUri = intent.clipData!!.getItemAt(0).uri
                    if (clipUri != null) {
                        result.add(clipUri)
                    }
                }
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val uris: ArrayList<Uri>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
                }
                if (uris != null) {
                    result.addAll(uris)
                } else if (intent.clipData != null) {
                    val count = intent.clipData!!.itemCount
                    for (i in 0 until count) {
                        val clipUri = intent.clipData!!.getItemAt(i).uri
                        if (clipUri != null) {
                            result.add(clipUri)
                        }
                    }
                }
            }
        }
        return result
    }

    fun resolveDisplayName(contentResolver: ContentResolver, uri: Uri): String {
        if (uri.scheme == ContentResolver.SCHEME_CONTENT) {
            val projection = arrayOf(OpenableColumns.DISPLAY_NAME)
            try {
                contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIndex != -1 && cursor.moveToFirst() && !cursor.isNull(nameIndex)) {
                        val name = cursor.getString(nameIndex)
                        if (!name.isNullOrEmpty()) {
                            return name
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed querying display name for $uri", e)
            }
        }
        return uri.lastPathSegment ?: "shared_file"
    }

    fun resolveFileSize(contentResolver: ContentResolver, uri: Uri): Long {
        if (uri.scheme == ContentResolver.SCHEME_CONTENT) {
            val projection = arrayOf(OpenableColumns.SIZE)
            try {
                contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                    val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (sizeIndex != -1 && cursor.moveToFirst() && !cursor.isNull(sizeIndex)) {
                        val size = cursor.getLong(sizeIndex)
                        if (size >= 0) {
                            return size
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed querying size for $uri", e)
            }
        }
        if (uri.scheme == ContentResolver.SCHEME_FILE && uri.path != null) {
            val file = File(uri.path!!)
            if (file.exists()) {
                return file.length()
            }
        }
        try {
            contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
                val statSize = pfd.statSize
                if (statSize >= 0) {
                    return statSize
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed inspecting statSize for $uri", e)
        }
        return -1L
    }

    fun copyToCache(
        contentResolver: ContentResolver,
        cacheDir: File,
        uri: Uri,
        filename: String
    ): SharedFileEntry? {
        val cacheSubdir = File(cacheDir, "shared_incoming").apply { mkdirs() }
        val prefix = "share_${System.currentTimeMillis()}_"
        val cleanName = filename.replace("[^a-zA-Z0-9._-]".toRegex(), "_")
        val destination = File(cacheSubdir, "$prefix$cleanName")
        return try {
            contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(destination).use { output ->
                    input.copyTo(output)
                }
            } ?: return null
            SharedFileEntry(
                name = filename,
                size = destination.length(),
                cachePath = destination.absolutePath,
                fd = null
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed copying stream to cache", e)
            null
        }
    }

    fun obtainDetachedFd(
        contentResolver: ContentResolver,
        uri: Uri,
        filename: String,
        knownSize: Long
    ): SharedFileEntry? {
        return try {
            val pfd = contentResolver.openFileDescriptor(uri, "r") ?: return null
            val statSize = pfd.statSize
            val rawFd = pfd.detachFd()
            val finalSize = if (knownSize >= 0) knownSize else if (statSize >= 0) statSize else 0L
            SharedFileEntry(
                name = filename,
                size = finalSize,
                cachePath = null,
                fd = rawFd
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed opening ParcelFileDescriptor", e)
            null
        }
    }

    fun processUri(
        context: Context,
        contentResolver: ContentResolver,
        cacheDir: File,
        uri: Uri
    ): SharedFileEntry? {
        val filename = resolveDisplayName(contentResolver, uri)
        val size = resolveFileSize(contentResolver, uri)
        return if (size >= LARGE_FILE_THRESHOLD_BYTES) {
            obtainDetachedFd(contentResolver, uri, filename, size)
        } else {
            copyToCache(contentResolver, cacheDir, uri, filename)
                ?: obtainDetachedFd(contentResolver, uri, filename, size)
        }
    }
}

class ShareTargetActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIncomingIntent(intent)
        finish()
    }

    private fun handleIncomingIntent(intent: Intent?) {
        if (intent == null) {
            return
        }

        val sharedFiles = ShareIntentProcessor.processIntent(
            this,
            contentResolver,
            cacheDir,
            intent
        )

        notifyMainActivity(intent, sharedFiles)
    }

    private fun notifyMainActivity(intent: Intent, sharedFiles: List<SharedFileEntry>) {
        val jsonArray = JSONArray()
        for (file in sharedFiles) {
            jsonArray.put(file.toJson())
        }
        val jsonString = jsonArray.toString()

        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            action = ACTION_SHARED_FILES
            type = intent.type
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_SHARED_FILES_JSON, jsonString)
            if (intent.hasExtra(Intent.EXTRA_TEXT)) {
                putExtra(Intent.EXTRA_TEXT, intent.getStringExtra(Intent.EXTRA_TEXT))
            }
            if (intent.hasExtra(EXTRA_TARGET_DEVICE)) {
                putExtra(EXTRA_TARGET_DEVICE, intent.getStringExtra(EXTRA_TARGET_DEVICE))
            }
        }
        if (launchIntent != null) {
            startActivity(launchIntent)
        } else {
            try {
                val fallbackIntent = Intent().apply {
                    setClassName(packageName, "com.tradr.app.MainActivity")
                    action = ACTION_SHARED_FILES
                    type = intent.type
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                    putExtra(EXTRA_SHARED_FILES_JSON, jsonString)
                    if (intent.hasExtra(Intent.EXTRA_TEXT)) {
                        putExtra(Intent.EXTRA_TEXT, intent.getStringExtra(Intent.EXTRA_TEXT))
                    }
                    if (intent.hasExtra(EXTRA_TARGET_DEVICE)) {
                        putExtra(EXTRA_TARGET_DEVICE, intent.getStringExtra(EXTRA_TARGET_DEVICE))
                    }
                }
                startActivity(fallbackIntent)
            } catch (e: Exception) {
                Log.e(TAG, "Failed starting main activity", e)
            }
        }
    }
}
