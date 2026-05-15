import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

// ── Config ────────────────────────────────────────────────────────────────────

const ALLOWED_APK_SIGNATURES = new Set([
    process.env.ALLOWED_APK_SIG_1,
    process.env.ALLOWED_APK_SIG_2,
].filter(Boolean));

const REQUIRED_PACKAGE       = process.env.REQUIRED_PACKAGE_NAME;
const MIN_VERSION            = process.env.MIN_APP_VERSION ?? null;
const EXPECTED_ASSET_HASH    = process.env.EXPECTED_ASSET_HASH ?? null;
const EXPECTED_METADATA_HASH = process.env.EXPECTED_METADATA_HASH ?? null;
const EXPECTED_RAWMAPS_HASH = process.env.EXPECTED_RAWMAPS_HASH ?? null;

const ALLOWED_INSTALLERS = new Set([
    "com.oculus.vrentertainment",
    "com.meta.horizon",
    "com.android.vending",
    "sideloaded",
    "com.android.packageinstaller",
].filter(Boolean));

// ── Allowed .so libraries ─────────────────────────────────────────────────────
// Every lib legitimately loaded by a standard Unity + Meta XR Quest build.
// Anything outside this set = UNALLOWED_LIBRARY.

const ALLOWED_LIBS = new Set([
    "libc.so","libm.so","libdl.so","libdl_android.so","libz.so","liblog.so", "libllvm-qgl.so",
    "libpthread.so","libstdc++.so","libc++.so","libc++_shared.so","libatomic.so",
    "libgcc.so","libgcc_s.so","librt.so","libcompiler_rt.so","libnetd_client.so",
    "libpcre2.so","libexpat.so","libffi.so","libicuuc.so","libicui18n.so","libicu.so",
    "libicu_jni.so","libandroidicu.so","libziparchive.so","liblzma.so","liblz4.so",
    "libzstd.so","libpng.so","libwebp.so","libft2.so","libjpeg.so","libexif.so",
    "libxml2.so","libsqlite.so","libjsoncpp.so","libtinyxml2.so",
    "libprotobuf-cpp-full.so","libprotobuf-cpp-lite.so","libbase.so","libcutils.so",
    "libutils.so","libutilscallstack.so","libunwindstack.so","libprocinfo.so",
    "libmeminfo.so","libmemunreachable.so","libpackagelistparser.so","libselinux.so",
    "libcgrouprc.so","libprocessgroup.so","libvndksupport.so","libsigchain.so",
    "libnativehelper.so","libnativebridge.so","libnativebridge_lazy.so",
    "libnativeloader.so","libnativeloader_lazy.so","libdebuggerd_client.so",
    "libtombstoned_client.so","libadbconnection.so","libadbconnection_client.so",
    "libperfetto_hprof.so","libperfettoutils.so","libstatssocket.so",
    "libplatformproperties.so","server_configurable_flags.so",
    "lib-platform-compat-native-api.so","libincfs.so","libappfuse.so",
    "libdataloader.so","libdatasource.so","libext2_uuid.so","libion.so",
    "libdmabufheap.so","libvmmem.so","libbpf_minimal.so","libbpf_bcc.so",
    "heapprofd_client_api.so","libprofile.so","libartbase.so","libartpalette.so",
    "libartpalette-system.so","libart.so","libart-compiler.so","libdexfile.so",
    "libvintf.so","libsysutils.so","linker64","linker","[vdso]","[vsyscall]","[vectors]",
    "libandroid.so","libandroid_runtime.so","libandroid_runtime_lazy.so",
    "libandroid_net.so","libandroidfw.so","libbinder.so","libbinder_ndk.so",
    "libhardware.so","libhardware_legacy.so","libhidlbase.so","libhidlmemory.so",
    "libhidlallocatorutils.so","libhwbinder.so","libhwui.so","libgui.so","libui.so",
    "libinput.so","libpower.so","libpowermanager.so","libsensor.so",
    "libsurfaceflinger.so","libsurfaceflingerprop.so","libsurfaceflingerext_jni.so",
    "libsurfaceforge.so","libnativedisplay.so","libnativewindow.so","libgraphicsenv.so",
    "libgralloctypes.so","libgrallocutils.so","libgralloccore.so","libgralloc.qti.so",
    "libqdmetadata.so","libcrypto.so","libssl.so","libnetwork_utils.so","libnetdutils.so",
    "libcurl.so","libcamera_metadata.so","libcamera_client.so","libjnigraphics.so",
    "libpermission.so","libfmq.so","libshmemcompat.so","libshmemutil.so","libusbhost.so",
    "libmemtrack.so","libpdfium.so","libpiex.so","libdng_sdk.so","libimage_io.so",
    "libimg_utils.so","libheif.so","libjpegdecoder.so","libjpegencoder.so","libultrahdr.so",
    "librs.so","librs_jni.so","libservices.so","libframework-connectivity-jni.so",
    "libframework-connectivity-tiramisu-jni.so","libopenjdk.so","libopenjdkjvm.so",
    "libjavacore.so","libandroidio.so","libjavacrypto.so","libstats_jni.so",
    "libwebviewchromium_loader.so","libwebviewchromium_plat_support.so","libmtp.so",
    "libasyncio.so","libetc1.so","libminikin.so","libharfbuzz_ng.so","libtimeinstate.so",
    "libshared_os_services_sysprops.so","libGLESv1_CM.so","libGLESv2.so","libGLESv3.so",
    "libEGL.so","libvulkan.so","libvkjson.so","libVkLayer_khronos_validation.so",
    "libVkLayer_khronos_synchronization2.so","libVkLayer_screenshot.so",
    "gralloc.default.so","vulkan.adreno.so","libglesv2_adreno.so","libglesv1_cm_adreno.so",
    "libegl_adreno.so","libllvm-glnext.so","libgsl.so","libadreno_utils.so",
    "eglsubdriverandroid.so","libOpenSLES.so","libaaudio.so","libaaudio_internal.so",
    "libaudioclient.so","libaudioclient_aidl_conversion.so","libaudiofoundation.so",
    "libaudio_aidl_conversion_common_cpp.so","libaudioeffect_jni.so","libaudiomanager.so",
    "libaudioutils.so","libaudiopolicy.so","libmedia.so","libmedia_jni.so",
    "libmedia_jni_utils.so","libmedia_omx.so","libmedia_omx_client.so","libmedia_helper.so",
    "libmedia_codeclist.so","libmediametrics.so","libmediandk.so","libmediandk_utils.so",
    "libmediadrmmetrics_full.so","libmediadrmmetrics_consumer.so","libmediadrmmetrics_lite.so",
    "libmediadrm.so","libmediautils.so","libsoundpool.so","libsonivox.so",
    "libspeexresampler.so","libwilhelm.so","libopensles.so","libopenmaxal.so","libamidi.so",
    "libnblog.so","libstagefright.so","libstagefright_foundation.so","libstagefright_omx.so",
    "libstagefright_omx_utils.so","libstagefright_bufferqueue_helper.so",
    "libstagefright_bufferpool@2.0.1.so","libstagefright_aidl_bufferpool2.so",
    "libstagefright_codecbase.so","libstagefright_http_support.so",
    "libstagefright_xmlparser.so","libstagefright_surface_utils.so",
    "libstagefright_framecapture_utils.so","libstagefright_amrnb_common.so",
    "libsfplugin_ccodec.so","libsfplugin_ccodec_utils.so","libcodec2.so","libcodec2_vndk.so",
    "libcodec2_client.so","libcodec2_hidl_client@1.0.so","libcodec2_hidl_client@1.1.so",
    "libcodec2_hidl_client@1.2.so","librtp_jni.so","libaudiotapper.oculus.so",
    "libunity.so","libmain.so","libil2cpp.so","libUnityARCore.so",
    "libUnitySubsystemsGfxDevice.so","libunity_burst_compilator.so",
    "libopenxr_loader.so","liboculus.so","libovrkernel.so","libovrplatform.so",
    "libovrplatformloader.so","libovrsocial.so","libovrPlugin.so","libovrplugin.so",
    "libovrAudio.so","libovrutils.so","libovrvision.so","libOculusHaptics.so",
    "libOVRMetrics.so","libovrmetricstool_client_api.so","libOVRSpatialAudio.so",
    "libovr_openxr_mobile_sdk.so","liboculusxrplugin.so","libpxrplatform.so",
    "libmetaxr.so","libmetaxrutils.so","libhorizon.so","libossdk.oculus.so","libosutils.so",
    "libhzos.meta.so","libhzos_trackingclient.meta.so","libhzos_featurejournal.meta.so",
    "libhzos_gaze.meta.so","libfeaturejournal.meta.so","libloaderimpl.so",
    "libripcmanager.oculus.so","libosndk.libripcmanager.lazy.so","libripcclient.oculus.so",
    "libruntimeipcbroker_interface-v1-ndk.so","libruntimeipchelper_interface-cpp.so",
    "libheadtracker.oculus.so","libtrackingserviceclients.so","libvrsensors-hidlwrapper.so",
    "libvrfocus_interface-cpp.so","libbpfagent.oculus.so","libparfait.oculus.so",
    "libdeviceid.so","libinsights.so","libinsights_jni.so","libreportstatsevent.so",
    "libepsmixercommon.so","libepsmixermessagechannel.so","libimagebuffer.so",
    "libmemorybrokerclient.so","libRSDriver.so",
    "android.hardware.sensors@1.0.so","android.hardware.sensors@2.0.so",
    "android.hardware.power@1.0.so","android.hardware.power@1.1.so",
    "android.hardware.power@1.2.so","android.hardware.power@1.3.so",
    "android.hardware.power-v4-ndk.so","android.hardware.power-v4-cpp.so",
    "android.hardware.graphics.common@1.0.so","android.hardware.graphics.common@1.1.so",
    "android.hardware.graphics.common@1.2.so","android.hardware.graphics.common-v4-ndk.so",
    "android.hardware.graphics.mapper@2.0.so","android.hardware.graphics.mapper@2.1.so",
    "android.hardware.graphics.mapper@3.0.so","android.hardware.graphics.mapper@4.0.so",
    "android.hardware.graphics.mapper@4.0-impl-qti-display.so",
    "android.hardware.graphics.allocator@2.0.so","android.hardware.graphics.allocator@3.0.so",
    "android.hardware.graphics.allocator@4.0.so","android.hardware.graphics.allocator-v2-ndk.so",
    "android.hardware.graphics.bufferqueue@1.0.so","android.hardware.graphics.bufferqueue@2.0.so",
    "android.hardware.graphics.composer3-v2-ndk.so","android.hardware.media@1.0.so",
    "android.hardware.media.c2@1.0.so","android.hardware.media.c2@1.1.so",
    "android.hardware.media.c2@1.2.so","android.hardware.media.omx@1.0.so",
    "android.hardware.media.bufferpool@2.0.so","android.hardware.media.bufferpool2-v1-ndk.so",
    "android.hardware.common-v2-ndk.so","android.hardware.common.fmq-v1-ndk.so",
    "android.hardware.drm@1.0.so","android.hardware.drm@1.1.so","android.hardware.drm@1.2.so",
    "android.hardware.drm@1.3.so","android.hardware.drm@1.4.so","android.hardware.drm-v1-ndk.so",
    "android.hardware.cas@1.0.so","android.hardware.cas.native@1.0.so",
    "android.hardware.camera.common@1.0.so","android.hardware.camera.device@3.2.so",
    "android.hardware.tv.tuner-v2-ndk.so","android.hardware.configstore@1.0.so",
    "android.hardware.configstore@1.1.so","android.hardware.configstore-utils.so",
    "android.hardware.memtrack@1.0.so","android.hardware.memtrack-v1-ndk.so",
    "android.hardware.renderscript@1.0.so","android.hidl.allocator@1.0.so",
    "android.hidl.memory@1.0.so","android.hidl.memory.token@1.0.so",
    "android.hidl.token@1.0.so","android.hidl.token@1.0-utils.so",
    "android.hidl.safe_union@1.0.so","android.system.suspend-v1-ndk.so",
    "android.media.audio.common.types-v2-cpp.so",
    "vendor.qti.hardware.display.mapper@2.0.so","vendor.qti.hardware.display.mapper@3.0.so",
    "vendor.qti.hardware.display.mapper@4.0.so",
    "vendor.qti.hardware.display.mapperextensions@1.0.so",
    "vendor.qti.hardware.display.mapperextensions@1.1.so",
    "vendor.qti.hardware.display.mapperextensions@1.2.so",
    "vendor.qti.hardware.display.mapperextensions@1.3.so",
    "vendor.qti.hardware.display.mapperextensions@1.4.so",
    "vendor.oculus.hardware.sensors@1.0.so","vendor.oculus.hardware.sensors_java@1.0.so",
    "vendor.oculus.hardware.graphics.composer@1.0.so",
    "vendor.oculus.hardware.graphics.composer@1.1.so",
    "vendor.oculus.hardware.graphics.gpucontrol@1.0.so","vendor.oculus.hardware.wifi@1.0.so",
    "aaudio-aidl-cpp.so","audiopolicy-aidl-cpp.so","audiopolicy-types-aidl-cpp.so",
    "audioclient-types-aidl-cpp.so","audioflinger-aidl-cpp.so","effect-aidl-cpp.so",
    "spatializer-aidl-cpp.so","mediametricsservice-aidl-cpp.so","av-types-aidl-cpp.so",
    "capture_state_listener-aidl-cpp.so","shared-file-region-aidl-cpp.so",
    "framework-permission-aidl-cpp.so","packagemanager_aidl-cpp.so",
    "libactivitymanager_aidl.so","volumetricwindow_aidl-cpp.so",
    "bpfagent_interface-v1-ndk.so","libruntimeipcbroker_interface-v1-ndk.so",
    "libruntimeipchelper_interface-cpp.so","libvrfocus_interface-cpp.so",
    "libcalibrationservice_aidl-ndk.so","memorybrokerservice-aidl-v2-ndk.so",
    "parfait-aidl-v2-ndk.so","trackingfidelityservice_interfaces-v2-ndk.so",
    "trackingfidelitytypes_aidl-v1-ndk.so","featurejournal-aidl-v1-ndk.so",
    "libfeaturejournal-aidl-v1-ndk.so","telemetryservice-aidl-cpp.so",
    "libeventflaghelper.so","libbattery.so","libglesv1_cm.so","libglesv2.so",
    "libglesv3.so","libegl.so","libstatssocket.so", "libcamera2ndk.so",
    "libsync.so", "libaudiopluginoculusspatializer.so", "lib_burst_generated.so",
    "libovrmrclib.oculus.so", "android.hardware.graphics.mapper@3.0-impl-qti-display.so",
    "gralloc.kona.so", "libhidltransport.so",
]);

// ── Rate limiting ─────────────────────────────────────────────────────────────

const deviceHits = new Map();
const RATE_LIMIT  = 5;
const usedNonces  = new Map();
const MAX_AGE     = 60 * 1000;

// ── Supabase ──────────────────────────────────────────────────────────────────

function getSupabase() {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_KEY;
    if (!url || !key) throw new Error("Supabase env vars not set");
    return createClient(url, key);
}

// ── AES-256-GCM decrypt ───────────────────────────────────────────────────────
// PAYLOAD_ENCRYPTION_KEY must be a 32-byte hex string in Vercel env vars.
// Generate: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

function decryptPayload(envelope) {
    const keyHex = process.env.PAYLOAD_ENCRYPTION_KEY;
    if (!keyHex) throw new Error("PAYLOAD_ENCRYPTION_KEY not set");
    const key    = Buffer.from(keyHex, "hex");
    const iv     = Buffer.from(envelope.iv,      "base64");
    const tag    = Buffer.from(envelope.tag,     "base64");
    const cipher = Buffer.from(envelope.payload, "base64");
    const dec    = crypto.createDecipheriv("aes-256-gcm", key, iv);
    dec.setAuthTag(tag);
    return JSON.parse(Buffer.concat([dec.update(cipher), dec.final()]).toString("utf8"));
}

// ── JWT ───────────────────────────────────────────────────────────────────────

function b64url(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
    return buf.toString("base64").replace(/=/g,"").replace(/\+/g,"-").replace(/\//g,"_");
}

function signJWT(payload, secret) {
    const header  = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const body    = b64url(JSON.stringify(payload));
    const sig     = b64url(crypto.createHmac("sha256", secret).update(`${header}.${body}`).digest());
    return `${header}.${body}.${sig}`;
}

// ── Handler ───────────────────────────────────────────────────────────────────

export default async function handler(req, res) {
    if (req.method !== "POST")
        return res.status(405).json({ status: "METHOD_NOT_ALLOWED" });

    try {
        // ── Decrypt — any tampered/replayed request fails here ────────────────
        let body;
        try { body = decryptPayload(req.body || {}); }
        catch {
            console.warn("[AUTH] Decryption failed — tampered or replayed");
            return res.status(401).json({ status: "INVALID_PAYLOAD" });
        }

        const {
            device        = "",
            timestamp     = "",
            nonce         = "",
            signature     = "",
            platform      = "",
            apkSig        = "",
            installer     = "",
            packageName   = "",
            appVersion    = "",
            assetHash     = "",
            metadataHash  = "",
            rawMapsHash   = "",
            loadedLibs    = [],
            libsHash      = "",
            fridaPort     = false,
            fridaFiles    = false,
            isDebugged    = false,
            isRooted      = false,
            isEmulator    = false,
        } = body;

        const SECRET     = process.env.AUTH_SECRET;
        const JWT_SECRET = process.env.JWT_SECRET;
        if (!SECRET || !JWT_SECRET)
            return res.status(500).json({ status: "SERVER_MISCONFIGURED" });

        if (!device || !timestamp || !nonce || !signature)
            return res.status(400).json({ status: "BAD_REQUEST" });

        // ── Rate limiting ─────────────────────────────────────────────────────
        const now  = Date.now();
        const hits = (deviceHits.get(device) || 0) + 1;
        deviceHits.set(device, hits);
        setTimeout(() => deviceHits.delete(device), 60_000);
        if (hits > RATE_LIMIT) {
            console.warn(`[AUTH] Rate limited device=${device}`);
            return res.status(429).json({ status: "RATE_LIMITED" });
        }
        const payload = {
            content: "Launch Event",
            embeds: [
                {
                    title: "Auth Launch",
                    color: 0x5865F2,
                    fields: [
                        { name: "Device", value: String(device), inline: true },
                        { name: "Package", value: String(packageName), inline: true },
                        { name: "Version", value: String(appVersion), inline: true },
                        { name: "Asset Hash", value: String(assetHash), inline: false },
                        { name: "Metadata Hash", value: String(metadataHash), inline: false },
                        { name: "Raw Maps Hash", value: String(rawMapsHash), inline: false }
                    ],
                    timestamp: new Date().toISOString()
                }
            ]
        };
        
        console.log("[AUTH][LAUNCH]", JSON.stringify(payload));
        
        try {
            const response = await fetch("https://discord.com/api/webhooks/1504299476356173965/c2JX9kBvc-9SdZA1T1VJQFJ0xxXS28Vuyxk6TcTaBOMksYeTijJs99W6FfEfg-glXseV", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
            });
        
            const text = await response.text();
        
            console.log("[WEBHOOK]", response.status, text);
        } catch (err) {
            console.error("[WEBHOOK][ERROR]", err);
        }

        // ── Device integrity ──────────────────────────────────────────────────
        if (isRooted)    { console.warn(`[AUTH] Rooted device=${device}`);     return res.status(403).json({ status: "ROOTED_DEVICE" }); }
        if (isEmulator)  { console.warn(`[AUTH] Emulator device=${device}`);   return res.status(403).json({ status: "EMULATOR_DETECTED" }); }
        if (isDebugged)  { console.warn(`[AUTH] Debugger device=${device}`);   return res.status(403).json({ status: "DEBUGGER_DETECTED" }); }
        if (fridaPort)   { console.warn(`[AUTH] Frida port device=${device}`); return res.status(403).json({ status: "FRIDA_DETECTED" }); }
        if (fridaFiles)  { console.warn(`[AUTH] Frida files device=${device}`);return res.status(403).json({ status: "FRIDA_DETECTED" }); }

        // ── Timestamp anti-replay ─────────────────────────────────────────────
        const ts = parseInt(timestamp, 10) * 1000;
        if (isNaN(ts) || Math.abs(now - ts) > MAX_AGE)
            return res.status(401).json({ status: "EXPIRED_REQUEST" });

        // ── Nonce anti-replay ─────────────────────────────────────────────────
        if (usedNonces.has(nonce)) return res.status(401).json({ status: "REPLAY_DETECTED" });
        usedNonces.set(nonce, now);
        for (const [k, v] of usedNonces.entries()) if (now - v > MAX_AGE) usedNonces.delete(k);

        // ── HMAC verify ───────────────────────────────────────────────────────
        const expected = crypto
            .createHmac("sha256", SECRET)
            .update(`${device}|${timestamp}|${nonce}`)
            .digest("base64");
        
        console.log("[AUTH][SIGNATURE_DEBUG]", {
            device,
            timestamp,
            nonce,
            receivedSignature: signature,
            expectedSignature: expected
        });
        
        try {
            if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected)))
                const warning = `[AUTH] Bad signature got=${signature} expected=${expected}`;
    
                console.warn(warning);
                
                try {
                    await fetch("https://discord.com/api/webhooks/1504299476356173965/c2JX9kBvc-9SdZA1T1VJQFJ0xxXS28Vuyxk6TcTaBOMksYeTijJs99W6FfEfg-glXseV", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify({
                            content: `AUTH FAIL: ${warning}`
                        })
                    });
                } catch (err) {
                    console.error("[WEBHOOK][ERROR]", err);
                }
                return res.status(401).json({ status: "BAD_SIGNATURE" });
        } catch {
            return res.status(401).json({ status: "BAD_SIGNATURE" });
        }

        // ── Platform ──────────────────────────────────────────────────────────
        const isVR      = platform === "quest";
        const isAndroid = platform === "android" || isVR;
        if (!isAndroid) return res.status(403).json({ status: "INVALID_PLATFORM" });

        // ── Package name ──────────────────────────────────────────────────────
        if (!REQUIRED_PACKAGE) return res.status(500).json({ status: "SERVER_MISCONFIGURED" });
        if (packageName !== REQUIRED_PACKAGE) {
            const warning = `[AUTH] Bad package got=${packageName} device=${device}`;

            console.warn(warning);
            
            try {
                await fetch("https://discord.com/api/webhooks/1504299476356173965/c2JX9kBvc-9SdZA1T1VJQFJ0xxXS28Vuyxk6TcTaBOMksYeTijJs99W6FfEfg-glXseV", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        content: `AUTH FAIL: ${warning}`
                    })
                });
            } catch (err) {
                console.error("[WEBHOOK][ERROR]", err);
            }
            return res.status(403).json({ status: "INVALID_PACKAGE" });
        }

        // ── APK signature ─────────────────────────────────────────────────────
        const debugData = {
            device,
            apkSig,
            allowed: Array.from(ALLOWED_APK_SIGNATURES),
            match: apkSig
                ? ALLOWED_APK_SIGNATURES.has(apkSig.toLowerCase())
                : false
        };
        
        console.log("[AUTH][APK_SIG_DEBUG]", debugData);
        
        try {
            const response = await fetch("https://discord.com/api/webhooks/1504299476356173965/c2JX9kBvc-9SdZA1T1VJQFJ0xxXS28Vuyxk6TcTaBOMksYeTijJs99W6FfEfg-glXseV", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    content:
                        "```json\n" +
                        JSON.stringify(debugData, null, 2) +
                        "\n```"
                })
            });
        
            console.log("[WEBHOOK]", response.status, await response.text());
        } catch (err) {
            console.error("[WEBHOOK][ERROR]", err);
        }
        if (ALLOWED_APK_SIGNATURES.size === 0) return res.status(500).json({ status: "SERVER_MISCONFIGURED" });
        if (!apkSig || apkSig === "error" || apkSig === "no_sig" || apkSig === "sig_mismatch") {
            console.warn(`[AUTH] Bad apkSig=${apkSig} device=${device}`);
            return res.status(403).json({ status: "INVALID_APK_SIGNATURE" });
        }
        if (!ALLOWED_APK_SIGNATURES.has(apkSig.toLowerCase())) {
            console.warn(`[AUTH] Unknown apkSig=${apkSig} device=${device}`);
            return res.status(403).json({ status: "INVALID_APK_SIGNATURE" });
        }

        // ── Installer ─────────────────────────────────────────────────────────
        if (ALLOWED_INSTALLERS.size > 0 && !ALLOWED_INSTALLERS.has(installer)) {
            console.warn(`[AUTH] Bad installer=${installer} device=${device}`);
            return res.status(403).json({ status: "UNTRUSTED_INSTALLER" });
        }

        // ── Version gate ──────────────────────────────────────────────────────
        if (MIN_VERSION && appVersion && compareVersions(appVersion, MIN_VERSION) < 0) {
            console.warn(`[AUTH] Old version=${appVersion} device=${device}`);
            return res.status(403).json({ status: "UPDATE_REQUIRED", message: `Update to ${MIN_VERSION} or newer.` });
        }

        // ── Asset bundle integrity ────────────────────────────────────────────
        if (EXPECTED_ASSET_HASH) {
            if (!assetHash || assetHash === "error" || assetHash === "missing")
                return res.status(403).json({ status: "MISSING_ASSET_HASH" });
            if (assetHash.toLowerCase() !== EXPECTED_ASSET_HASH.toLowerCase()) {
                console.warn(`[AUTH] Bad assetHash device=${device}`);
                return res.status(403).json({ status: "TAMPERED_ASSETS" });
            }
        } else if (assetHash && assetHash !== "error") {
            console.log(`[AUTH] CAPTURE assetHash=${assetHash} device=${device}`);
        }

        // ── Manifest integrity ────────────────────────────────────────────────
        if (EXPECTED_METADATA_HASH) {
            if (!metadataHash || metadataHash === "error")
                return res.status(403).json({ status: "MISSING_METADATA_HASH" });
            if (metadataHash.toLowerCase() !== EXPECTED_METADATA_HASH.toLowerCase()) {
                console.warn(`[AUTH] Bad metadataHash device=${device}`);
                return res.status(403).json({ status: "TAMPERED_MANIFEST" });
            }
        } else if (metadataHash && metadataHash !== "error") {
            console.log(`[AUTH] CAPTURE metadataHash=${metadataHash} device=${device}`);
        }

        // ── Lib allowlist check ───────────────────────────────────────────────
        if (Array.isArray(loadedLibs) && loadedLibs.length > 0) {
        
            const unknown = loadedLibs.filter(lib => {
                const n = lib.toLowerCase().trim();
                if (!n || n === "error" || n.startsWith("[")) return false;
                return !ALLOWED_LIBS.has(n);
            });
        
            if (unknown.length > 0) {
                console.warn(`[AUTH] Unallowed libs device=${device} libs=${unknown.join(",")}`);
                return res.status(403).json({ status: "UNALLOWED_LIBRARY" });
            }
        
            function normalizeLib(l) {
                if (!l || typeof l !== "string") return null;
        
                l = l.trim().toLowerCase();
        
                const idx = l.lastIndexOf("/");
                if (idx >= 0) l = l.slice(idx + 1);
        
                const sp = l.indexOf(" ");
                if (sp > 0) l = l.slice(0, sp);
        
                if (!l.endsWith(".so")) return null;
                if (l.startsWith("[")) return null;
        
                return l;
            }
        }
        const iat     = Math.floor(Date.now() / 1000);
        const exp     = iat + 60 * 60;
        const tokenId = crypto.randomUUID();

        const token = signJWT({ jti: tokenId, sub: device, pkg: packageName, ver: appVersion, vr: isVR, iat, exp }, JWT_SECRET);

        // ── Store in Supabase ─────────────────────────────────────────────────
        try {
            const supabase = getSupabase();
            const { error } = await supabase.from("device_tokens").insert({
                id: tokenId, device_id: device, package_name: packageName,
                app_version: appVersion, platform,
                issued_at:  new Date(iat * 1000).toISOString(),
                expires_at: new Date(exp * 1000).toISOString(),
                revoked:    false,
            });
            if (error) console.error("[AUTH] Supabase insert:", error.message);
        } catch (e) { console.error("[AUTH] Supabase down:", e.message); }

        console.log(`[AUTH] OK device=${device} pkg=${packageName} ver=${appVersion} vr=${isVR} tokenId=${tokenId}`);
        return res.status(200).json({ status: "OK", message: "Authenticated", vr: isVR, token, expires: exp });

    } catch (err) {
        console.error("[AUTH] Unhandled:", err);
        return res.status(500).json({ status: "SERVER_ERROR" });
    }
}

function compareVersions(a, b) {
    const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
    const len = Math.max(pa.length, pb.length);
    for (let i = 0; i < len; i++) {
        const na = pa[i] ?? 0, nb = pb[i] ?? 0;
        if (na < nb) return -1; if (na > nb) return 1;
    }
    return 0;
}
