package com.example.kotlin_library

import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager


import android.os.Build
import android.os.Debug
import android.os.Environment
import android.provider.Settings
import android.view.WindowManager
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object SecurityLibrary {

    fun collectSecurityData(context: Context): Map<String, String> {
        return mapOf(
            "is_frida_detected" to detectFrida().toString(),
            "is_magisk_detected" to detectMagisk().toString(),
            "is_developer_options_enabled" to isDeveloperOptionsEnabled(context).toString(),
            "is_debugger_connected" to Debug.isDebuggerConnected().toString(),
            "is_emulator_detected" to detectEmulator().toString(),
            "harmful_apps_installed" to checkHarmfulApps(context).toString(),
            "remaining_storage" to getAvailableStorage().toString(),
            "available_ram" to getAvailableRAM(context).toString(),
            "is_ssl_pinned" to performSSLPinning().toString(),
            "is_repackaged" to checkRepackaging(context).toString(),
            "is_screen_overlay_detected" to detectScreenOverlay(context).toString(),
//            "is_biometric_available" to isBiometricAvailable(context).toString()
        )
    }
    // Frida detection logic
    private fun detectFrida(): Boolean {
        val fridaProcess = listOf("frida-server", "frida-agent", "frida")
        val runningProcesses = File("/proc").listFiles()?.map { it.name } ?: return false
        return runningProcesses.any { it in fridaProcess }
    }
    // Magisk detection logic
    private fun detectMagisk(): Boolean {
        val magiskPaths = arrayOf(
            "/sbin/magisk", "/sbin/magiskhide", "/system/xbin/su",
            "/system/bin/magisk", "/system/xbin/magisk"
        )
        return magiskPaths.any { path -> File(path).exists() }
    }
    // Developer options check
    private fun isDeveloperOptionsEnabled(context: Context): Boolean {
        return Settings.Global.getInt(
            context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) != 0
    }
// Harmful apps check

    private fun checkHarmfulApps(context: Context): Boolean {
        val harmfulApps = listOf("com.topjohnwu.magisk", "com.noshufou.android.su",
            "com.thirdparty.superuser")
        val pm = context.packageManager
        return harmfulApps.any { app -> isAppInstalled(pm, app) }
    }
    private fun isAppInstalled(pm: PackageManager, packageName: String): Boolean {
        return try {
            pm.getPackageInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }
    // Emulator detection logic
    private fun detectEmulator(): Boolean {
        return Build.FINGERPRINT.contains("generic") || Build.MODEL.contains("Emulator")
    }
    // Remaining storage check
    private fun getAvailableStorage(): Long {
        return File(Environment.getDataDirectory().path).usableSpace / (1024 * 1024) // in MB
    }
    // Available RAM check
    private fun getAvailableRAM(context: Context): Long {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as
                ActivityManager
        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)
        return memoryInfo.availMem / (1024 * 1024) // in MB
    }
    // SSL Pinning implementation
    private fun performSSLPinning(): Boolean {
        try {
            val pinnedCert = "<Your Base64 Encoded Certificate>"
            val cf = CertificateFactory.getInstance("X.509")
            val cert = cf.generateCertificate(pinnedCert.byteInputStream())
            val pinnedKey = cert.publicKey

            val trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trustManagerFactory.init(null as KeyStore?)
            val trustManagers = trustManagerFactory.trustManagers
            for (trustManager in trustManagers) {
                if (trustManager is X509TrustManager) {
                    for (cert in trustManager.acceptedIssuers) {
                        if (cert.publicKey == pinnedKey) {
                            return true
                        }
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }
    // Repackaging check
    private fun checkRepackaging(context: Context): Boolean {
        val expectedSignature = "<Your App’s Known Signature>"
        val actualSignature = getSignature(context)
        return actualSignature == expectedSignature
    }
    private fun getSignature(context: Context): String {
        val pm = context.packageManager
        val packageInfo = pm.getPackageInfo(context.packageName,
            PackageManager.GET_SIGNATURES)
        val signature = packageInfo.signatures[0].toByteArray()
        return MessageDigest.getInstance("SHA-256").digest(signature).joinToString("") {
            "%02x".format(it) }
    }
    // Screen overlay detection
    private fun detectScreenOverlay(context: Context): Boolean {
        val overlayApps =
            context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { it.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 }
        return overlayApps.isNotEmpty()
    }

    // Biometric availability check
//    private fun isBiometricAvailable(context: Context): Boolean {
//        return BiometricManager.from(context).canAuthenticate() ==
//                BiometricManager.BIOMETRIC_SUCCESS
//    }
// Additional anti-tampering and security checks can be added here...
}