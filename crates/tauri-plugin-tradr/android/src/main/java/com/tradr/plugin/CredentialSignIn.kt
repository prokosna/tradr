package com.tradr.plugin

import android.app.Activity
import androidx.core.content.ContextCompat
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.CredentialOption
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
import org.json.JSONObject

@InvokeArg
class SignInArgs {
    var serverClientId: String = ""
    var nonce: String = ""
}

class CredentialSignIn(private val activity: Activity) {

    private val credentialManager = CredentialManager.create(activity)

    fun signIn(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(SignInArgs::class.java)
        } catch (e: Exception) {
            resolveFailure(invoke, "googleId", e.javaClass.name, e.message ?: "Failed to parse arguments")
            return
        }

        // A user-started sign-in always shows the chooser so a wrong account can be replaced.
        requestSignInWithGoogle(args, invoke)
    }

    // Background renewal: only the saved-credential option, never the explicit
    // account picker, so a refusal surfaces as a failure instead of a screen.
    fun signInSilently(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(SignInArgs::class.java)
        } catch (e: Exception) {
            resolveFailure(invoke, "googleId", e.javaClass.name, e.message ?: "Failed to parse arguments")
            return
        }

        requestGoogleId(args, invoke)
    }

    private fun requestGoogleId(args: SignInArgs, invoke: Invoke) {
        val option = try {
            GetGoogleIdOption.Builder()
                .setServerClientId(args.serverClientId)
                .setNonce(args.nonce)
                .setFilterByAuthorizedAccounts(true)
                .setAutoSelectEnabled(true)
                .build()
        } catch (e: Exception) {
            resolveFailure(invoke, "googleId", e.javaClass.name, e.message ?: "Failed to build GetGoogleIdOption")
            return
        }

        performCredentialRequest(invoke, option, "googleId")
    }

    private fun requestSignInWithGoogle(args: SignInArgs, invoke: Invoke) {
        val option = try {
            GetSignInWithGoogleOption.Builder(args.serverClientId)
                .setNonce(args.nonce)
                .build()
        } catch (e: Exception) {
            resolveFailure(invoke, "signInWithGoogle", e.javaClass.name, e.message ?: "Failed to build GetSignInWithGoogleOption")
            return
        }

        performCredentialRequest(invoke, option, "signInWithGoogle")
    }

    private fun performCredentialRequest(
        invoke: Invoke,
        option: CredentialOption,
        label: String
    ) {
        val request = GetCredentialRequest.Builder()
            .addCredentialOption(option)
            .build()

        val callback = object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
            override fun onResult(result: GetCredentialResponse) {
                handleCredentialResult(result, label, invoke)
            }

            override fun onError(e: GetCredentialException) {
                resolveFailure(invoke, label, e.javaClass.name, e.message ?: "GetCredentialException")
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
            resolveFailure(invoke, label, e.javaClass.name, e.message ?: "Failed to initiate getCredentialAsync")
        }
    }

    private fun handleCredentialResult(
        result: GetCredentialResponse,
        optionClass: String,
        invoke: Invoke
    ) {
        val credential = result.credential
        if (credential is CustomCredential && credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
            try {
                val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)
                val response = JSObject()
                response.put("success", true)
                response.put("idToken", googleIdTokenCredential.idToken)
                response.put("optionClass", optionClass)
                response.put("errorClass", JSONObject.NULL)
                response.put("errorMessage", JSONObject.NULL)
                invoke.resolve(response)
            } catch (e: Exception) {
                resolveFailure(invoke, optionClass, e.javaClass.name, e.message ?: "Failed to parse GoogleIdTokenCredential")
            }
        } else {
            resolveFailure(invoke, optionClass, "UnexpectedCredentialType", "Unexpected credential type: ${credential.type}")
        }
    }

    private fun resolveFailure(
        invoke: Invoke,
        optionClass: String,
        errorClass: String,
        errorMessage: String
    ) {
        val response = JSObject()
        response.put("success", false)
        response.put("idToken", JSONObject.NULL)
        response.put("optionClass", optionClass)
        response.put("errorClass", errorClass)
        response.put("errorMessage", errorMessage)
        invoke.resolve(response)
    }
}
