package com.tradr.plugin

import android.app.Activity
import androidx.core.content.ContextCompat
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialException
import app.tauri.annotation.InvokeArg
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential

@InvokeArg
class ProbeCredentialArgs {
    var serverClientId: String = ""
    var nonce: String = ""
    var optionClass: String = ""
}

class CredentialProbe(private val activity: Activity) {

    private val credentialManager = CredentialManager.create(activity)

    fun getCredential(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(ProbeCredentialArgs::class.java)
        } catch (e: Exception) {
            val response = JSObject()
            response.put("success", false)
            response.put("errorClass", e.javaClass.name)
            response.put("errorMessage", e.message ?: "Failed to parse arguments")
            invoke.resolve(response)
            return
        }

        val credentialOption = try {
            when (args.optionClass) {
                "googleId" -> {
                    // Filtering authorized accounts yields NoCredentialException without prior authorization, masking client ID refusals.
                    GetGoogleIdOption.Builder()
                        .setServerClientId(args.serverClientId)
                        .setNonce(args.nonce)
                        .setFilterByAuthorizedAccounts(false)
                        .setAutoSelectEnabled(false)
                        .build()
                }
                "signInWithGoogle" -> {
                    GetSignInWithGoogleOption.Builder(args.serverClientId)
                        .setNonce(args.nonce)
                        .build()
                }
                else -> throw IllegalArgumentException("Unsupported optionClass: ${args.optionClass}")
            }
        } catch (e: Exception) {
            val response = JSObject()
            response.put("success", false)
            response.put("errorClass", e.javaClass.name)
            response.put("errorMessage", e.message ?: "Failed to build credential option")
            invoke.resolve(response)
            return
        }

        val request = GetCredentialRequest.Builder()
            .addCredentialOption(credentialOption)
            .build()

        val callback = object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
            override fun onResult(result: GetCredentialResponse) {
                val credential = result.credential
                if (credential is CustomCredential && credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                    try {
                        val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)
                        val response = JSObject()
                        response.put("success", true)
                        response.put("idToken", googleIdTokenCredential.idToken)
                        invoke.resolve(response)
                    } catch (e: Exception) {
                        val response = JSObject()
                        response.put("success", false)
                        response.put("errorClass", e.javaClass.name)
                        response.put("errorMessage", e.message ?: "Failed to parse GoogleIdTokenCredential")
                        invoke.resolve(response)
                    }
                } else {
                    val response = JSObject()
                    response.put("success", false)
                    response.put("errorClass", "UnexpectedCredentialType")
                    response.put("errorMessage", "Unexpected credential type: ${credential.type}")
                    invoke.resolve(response)
                }
            }

            override fun onError(e: GetCredentialException) {
                val response = JSObject()
                response.put("success", false)
                response.put("errorClass", e.javaClass.name)
                response.put("errorMessage", e.message ?: "GetCredentialException")
                invoke.resolve(response)
            }
        }

        try {
            credentialManager.getCredentialAsync(
                activity,
                request,
                null,
                ContextCompat.getMainExecutor(activity),
                callback
            )
        } catch (e: Exception) {
            val response = JSObject()
            response.put("success", false)
            response.put("errorClass", e.javaClass.name)
            response.put("errorMessage", e.message ?: "Failed to initiate getCredentialAsync")
            invoke.resolve(response)
        }
    }
}
