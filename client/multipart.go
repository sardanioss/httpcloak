package client

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
)

// FormFile represents a file to upload
type FormFile struct {
	FieldName string    // Form field name
	FileName  string    // File name
	Content   io.Reader // File content
	MIMEType  string    // MIME type (optional, will be detected)
}

// FormData represents multipart form data
type FormData struct {
	Fields map[string]string // Regular form fields
	Files  []FormFile        // Files to upload
}

// NewFormData creates a new FormData instance
func NewFormData() *FormData {
	return &FormData{
		Fields: make(map[string]string),
		Files:  make([]FormFile, 0),
	}
}

// AddField adds a form field
func (f *FormData) AddField(name, value string) *FormData {
	f.Fields[name] = value
	return f
}

// AddFile adds a file from bytes
func (f *FormData) AddFile(fieldName, fileName string, content []byte) *FormData {
	f.Files = append(f.Files, FormFile{
		FieldName: fieldName,
		FileName:  fileName,
		Content:   bytes.NewReader(content),
		MIMEType:  detectMIMEType(fileName),
	})
	return f
}

// AddFileReader adds a file from an io.Reader
func (f *FormData) AddFileReader(fieldName, fileName string, content io.Reader, mimeType string) *FormData {
	if mimeType == "" {
		mimeType = detectMIMEType(fileName)
	}
	f.Files = append(f.Files, FormFile{
		FieldName: fieldName,
		FileName:  fileName,
		Content:   content,
		MIMEType:  mimeType,
	})
	return f
}

// AddFilePath adds a file from a filesystem path
func (f *FormData) AddFilePath(fieldName, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	// Note: The file will be read when Encode is called
	// The caller is responsible for closing the file after the request is made

	f.Files = append(f.Files, FormFile{
		FieldName: fieldName,
		FileName:  filepath.Base(filePath),
		Content:   file,
		MIMEType:  detectMIMEType(filePath),
	})
	return nil
}

// Encode encodes the form data as multipart/form-data
// Returns the body bytes and the Content-Type header value (with boundary)
func (f *FormData) Encode() ([]byte, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add regular fields
	for name, value := range f.Fields {
		if err := writer.WriteField(name, value); err != nil {
			return nil, "", fmt.Errorf("failed to write field %s: %w", name, err)
		}
	}

	// Add files
	for _, file := range f.Files {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
			escapeQuotes(file.FieldName), escapeQuotes(file.FileName)))
		h.Set("Content-Type", file.MIMEType)

		part, err := writer.CreatePart(h)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create part for %s: %w", file.FieldName, err)
		}

		if _, err := io.Copy(part, file.Content); err != nil {
			return nil, "", fmt.Errorf("failed to copy file content for %s: %w", file.FieldName, err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	return buf.Bytes(), writer.FormDataContentType(), nil
}

// escapeQuotes escapes quotes in a string for use in Content-Disposition header
func escapeQuotes(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

// detectMIMEType detects MIME type from filename
func detectMIMEType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))

	mimeTypes := map[string]string{
		".html": "text/html",
		".htm":  "text/html",
		".css":  "text/css",
		".js":   "application/javascript",
		".json": "application/json",
		".xml":  "application/xml",
		".txt":  "text/plain",
		".csv":  "text/csv",

		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".svg":  "image/svg+xml",
		".ico":  "image/x-icon",
		".bmp":  "image/bmp",

		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".ogg":  "audio/ogg",
		".m4a":  "audio/mp4",

		".mp4":  "video/mp4",
		".webm": "video/webm",
		".avi":  "video/x-msvideo",
		".mov":  "video/quicktime",

		".pdf":  "application/pdf",
		".zip":  "application/zip",
		".gz":   "application/gzip",
		".tar":  "application/x-tar",
		".rar":  "application/vnd.rar",
		".7z":   "application/x-7z-compressed",

		".doc":  "application/msword",
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".xls":  "application/vnd.ms-excel",
		".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".ppt":  "application/vnd.ms-powerpoint",
		".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	}

	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}
