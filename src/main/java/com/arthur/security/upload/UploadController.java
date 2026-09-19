package com.arthur.security.upload;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * Hardened upload endpoint. All the safety is in {@link UploadService#store}.
 */
@RestController
public class UploadController {

    private final UploadService uploadService;

    public UploadController(UploadService uploadService) {
        this.uploadService = uploadService;
    }

    @PostMapping("/api/upload")
    public String upload(@RequestParam("file") MultipartFile file) {
        return "stored as " + uploadService.store(file);
    }
}
