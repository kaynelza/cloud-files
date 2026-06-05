package entity

import "time"

const (
	AuthTokenKey          = "auth_token"
	DefaultChunkSize      = 5 * 1024 * 1024
	UploadSessionLifetime = 24 * time.Hour
)

// AllowedMIMETypes представляет собой множество разрешенных MIME-типов.
var AllowedMIMETypes = map[string]struct{}{
	// Текстовые форматы
	"text/plain; charset=utf-8":      {},
	"text/html; charset=utf-8":       {},
	"text/css; charset=utf-8":        {},
	"text/javascript; charset=utf-8": {},

	// Данные и формы
	"application/json":                  {},
	"application/xml":                   {},
	"application/x-www-form-urlencoded": {},
	"application/octet-stream":          {},
	"multipart/form-data":               {},

	// Изображения
	"image/png":     {},
	"image/jpeg":    {},
	"image/gif":     {},
	"image/svg+xml": {},
	"image/x-icon":  {},
	"image/webp":    {},

	// Архивы и документы
	"application/pdf": {},
	"application/zip": {},

	// Аудио и видео
	"audio/mpeg": {},
	"audio/wav":  {},
	"video/mp4":  {},
	"video/webm": {},
}
