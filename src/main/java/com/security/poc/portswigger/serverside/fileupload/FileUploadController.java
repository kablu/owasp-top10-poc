package com.security.poc.portswigger.serverside.fileupload;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * PortSwigger topic: <b>File upload vulnerabilities</b>.
 * <a href="https://portswigger.net/web-security/file-upload">Reference</a>
 *
 * <p>An avatar upload. The vulnerable handler trusts the client-supplied filename
 * and content type, letting an attacker upload a web shell ({@code shell.jsp},
 * {@code shell.php}) that the server might later execute. The secure handler
 * validates the real content, restricts the extension via an allowlist, and
 * renames the file so it can never be requested/executed by its original name.
 *
 * <p>Send as multipart/form-data with a {@code file} part.
 */
@RestController
@RequestMapping("/ps/serverside/fileupload")
public class FileUploadController {

    private static final Set<String> ALLOWED_EXT = Set.of("png", "jpg", "jpeg", "gif");
    private static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/jpeg", "image/gif");
    private static final long MAX_BYTES = 2 * 1024 * 1024;   // 2 MB

    // -----------------------------------------------------------------------
    // VULNERABLE
    // Stores the file under its original, attacker-controlled name with no type
    // or size checks. Upload "shell.jsp" and, if it lands in an executable path,
    // requesting it runs code. Also vulnerable to path traversal in the name.
    // -----------------------------------------------------------------------
    @PostMapping("/vuln/upload")
    public Map<String, Object> vulnUpload(@RequestParam("file") MultipartFile file) {
        String name = file.getOriginalFilename();      // trusted blindly
        // Files.copy(file.getInputStream(), webroot.resolve(name));  // <-- would drop a shell
        return Map.of(
            "storedAs", String.valueOf(name),
            "contentType", String.valueOf(file.getContentType()),
            "sizeBytes", file.getSize(),
            "note", "Original name + type trusted. A .jsp/.php here could be executed."
        );
    }

    // -----------------------------------------------------------------------
    // SECURE
    //   1) Enforce a size limit.
    //   2) Allowlist the extension AND the declared content type.
    //   3) (Real systems also sniff magic bytes and re-encode images.)
    //   4) Generate a fresh random name + safe extension; store OUTSIDE the
    //      web root / serve via a handler, never by direct path.
    // -----------------------------------------------------------------------
    @PostMapping("/secure/upload")
    public ResponseEntity<?> secureUpload(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty() || file.getSize() > MAX_BYTES) {
            return ResponseEntity.badRequest().body(Map.of("error", "empty or too large (max 2MB)"));
        }
        String original = file.getOriginalFilename() == null ? "" : file.getOriginalFilename();
        String ext = original.contains(".") ? original.substring(original.lastIndexOf('.') + 1).toLowerCase() : "";
        if (!ALLOWED_EXT.contains(ext) || !ALLOWED_TYPES.contains(file.getContentType())) {
            return ResponseEntity.badRequest().body(Map.of("error", "only image files (png/jpg/gif) allowed",
                    "seenExt", ext, "seenType", String.valueOf(file.getContentType())));
        }
        String safeName = java.util.UUID.randomUUID() + "." + ext;   // never the original name
        return ResponseEntity.ok(Map.of("storedAs", safeName, "servedVia", "download handler, not direct path",
                "allowed", List.of("png", "jpg", "jpeg", "gif")));
    }
}
