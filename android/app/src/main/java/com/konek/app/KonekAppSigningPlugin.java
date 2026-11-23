package com.konek.app;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.security.MessageDigest;
import java.util.Locale;

/**
 * Reports the signing certificate fingerprints of the installed build.
 *
 * Google's Credential Manager only offers accounts to an app that has an
 * Android OAuth client registered for its package name + SHA-1 fingerprint.
 * When Google sign-in fails with "No Google account available" on a device
 * that does have a Google account, the values returned here are the ones that
 * must be added to the Android OAuth client in Google Cloud Console.
 */
@CapacitorPlugin(name = "KonekAppSigning")
public class KonekAppSigningPlugin extends Plugin {

    @PluginMethod
    public void getInfo(PluginCall call) {
        try {
            String packageName = getContext().getPackageName();
            Signature[] signatures = readSignatures(packageName);

            if (signatures == null || signatures.length == 0) {
                call.reject("No signing certificates found for " + packageName);
                return;
            }

            JSArray sha1 = new JSArray();
            JSArray sha256 = new JSArray();
            for (Signature signature : signatures) {
                sha1.put(toHexDigest(signature.toByteArray(), "SHA-1"));
                sha256.put(toHexDigest(signature.toByteArray(), "SHA-256"));
            }

            JSObject result = new JSObject();
            result.put("packageName", packageName);
            result.put("sha1", sha1);
            result.put("sha256", sha256);
            call.resolve(result);
        } catch (Exception error) {
            call.reject("Could not read the signing certificate: " + error.getMessage(), error);
        }
    }

    private Signature[] readSignatures(String packageName) throws PackageManager.NameNotFoundException {
        PackageManager packageManager = getContext().getPackageManager();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageInfo info = packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
            );
            if (info.signingInfo == null) {
                return null;
            }
            return info.signingInfo.hasMultipleSigners()
                    ? info.signingInfo.getApkContentsSigners()
                    : info.signingInfo.getSigningCertificateHistory();
        }

        @SuppressWarnings("deprecation")
        PackageInfo info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
        return info.signatures;
    }

    private String toHexDigest(byte[] certificate, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] bytes = digest.digest(certificate);
        StringBuilder builder = new StringBuilder(bytes.length * 3);
        for (byte value : bytes) {
            if (builder.length() > 0) {
                builder.append(':');
            }
            builder.append(String.format(Locale.US, "%02X", value));
        }
        return builder.toString();
    }
}
