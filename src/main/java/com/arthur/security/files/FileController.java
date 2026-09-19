package com.arthur.security.files;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves files from the public directory. All the safety lives in {@link FileStorageService#read}.
 */
@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileStorageService files;

    public FileController(FileStorageService files) {
        this.files = files;
    }

    @GetMapping(produces = MediaType.TEXT_PLAIN_VALUE)
    public String read(@RequestParam String name) {
        return files.read(name);
    }
}
