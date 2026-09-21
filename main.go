package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func main() {
	dbPath := envOr("DB_PATH", "/data/whisper.db")
	serverKey := envOr("SERVER_KEY", "change-me-in-production")
	listenAddr := envOr("LISTEN_ADDR", ":8000")

	os.MkdirAll(filepath.Dir(dbPath), 0755)

	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id TEXT PRIMARY KEY,
		content BLOB NOT NULL,
		nonce BLOB NOT NULL,
		password_hash TEXT,
		max_views INTEGER NOT NULL,
		views INTEGER DEFAULT 0,
		expires_at INTEGER NOT NULL,
		created_at INTEGER NOT NULL
	)`)

	key := deriveKey(serverKey)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/secrets", func(w http.ResponseWriter, r *http.Request) { handleCreate(w, r, key) })
	mux.HandleFunc("POST /api/secrets/{id}", func(w http.ResponseWriter, r *http.Request) { handleView(w, r, key) })
	mux.HandleFunc("GET /api/secrets/{id}/info", handleInfo)
	viewHTML, _ := os.ReadFile("static/view.html")
	mux.HandleFunc("GET /secret/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(viewHTML)
	})
	mux.Handle("GET /{path...}", http.FileServer(http.Dir("static")))

	log.Printf("Whisper listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func deriveKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func encrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

func decrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func hashPassword(pwd string) string {
	h := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(h[:])
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func cleanupExpired() {
	now := time.Now().Unix()
	db.Exec("DELETE FROM secrets WHERE expires_at <= ?", now)
	db.Exec("DELETE FROM secrets WHERE views >= max_views")
}

var durations = map[string]int64{
	"5m":  300,
	"30m": 1800,
	"1h":  3600,
	"24h": 86400,
	"7d":  604800,
}

type createReq struct {
	Content  string `json:"content"`
	Password string `json:"password"`
	Duration string `json:"duration"`
	MaxViews int    `json:"max_views"`
}

func handleCreate(w http.ResponseWriter, r *http.Request, key []byte) {
	cleanupExpired()

	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}

	content := strings.TrimSpace(req.Content)
	if content == "" || len(content) > 50000 {
		jsonError(w, "Content must be between 1 and 50000 characters", 400)
		return
	}

	dur, ok := durations[req.Duration]
	if !ok {
		dur = durations["24h"]
	}

	if req.MaxViews < 1 {
		req.MaxViews = 1
	}
	if req.MaxViews > 100 {
		req.MaxViews = 100
	}

	ciphertext, nonce, err := encrypt(key, []byte(content))
	if err != nil {
		jsonError(w, "Encryption error", 500)
		return
	}

	id := randomID()
	now := time.Now().Unix()
	expiresAt := now + dur

	var pwdHash *string
	if req.Password != "" {
		h := hashPassword(req.Password)
		pwdHash = &h
	}

	_, err = db.Exec(
		"INSERT INTO secrets (id, content, nonce, password_hash, max_views, views, expires_at, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
		id, ciphertext, nonce, pwdHash, req.MaxViews, expiresAt, now,
	)
	if err != nil {
		jsonError(w, "Database error", 500)
		return
	}

	jsonResp(w, 200, map[string]any{"id": id, "expires_at": expiresAt})
}

type viewReq struct {
	Password string `json:"password"`
}

func handleView(w http.ResponseWriter, r *http.Request, key []byte) {
	cleanupExpired()
	secretID := r.PathValue("id")

	var req viewReq
	json.NewDecoder(r.Body).Decode(&req)

	var content, nonce []byte
	var pwdHash sql.NullString
	var maxViews, views int
	var expiresAt int64

	err := db.QueryRow(
		"SELECT content, nonce, password_hash, max_views, views, expires_at FROM secrets WHERE id = ?", secretID,
	).Scan(&content, &nonce, &pwdHash, &maxViews, &views, &expiresAt)

	if err != nil {
		jsonError(w, "Secret not found or expired", 404)
		return
	}

	if views >= maxViews {
		db.Exec("DELETE FROM secrets WHERE id = ?", secretID)
		jsonError(w, "Secret not found or expired", 404)
		return
	}

	if pwdHash.Valid {
		if req.Password == "" {
			jsonError(w, "Password required", 401)
			return
		}
		h := hashPassword(req.Password)
		if subtle.ConstantTimeCompare([]byte(h), []byte(pwdHash.String)) != 1 {
			jsonError(w, "Wrong password", 403)
			return
		}
	}

	plaintext, err := decrypt(key, content, nonce)
	if err != nil {
		jsonError(w, "Decryption error", 500)
		return
	}

	db.Exec("UPDATE secrets SET views = views + 1 WHERE id = ?", secretID)
	remaining := maxViews - views - 1

	jsonResp(w, 200, map[string]any{
		"content":         string(plaintext),
		"remaining_views": remaining,
		"expires_at":      expiresAt,
	})
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	cleanupExpired()
	secretID := r.PathValue("id")

	var pwdHash sql.NullString
	var maxViews, views int
	var expiresAt int64

	err := db.QueryRow(
		"SELECT password_hash, max_views, views, expires_at FROM secrets WHERE id = ?", secretID,
	).Scan(&pwdHash, &maxViews, &views, &expiresAt)

	if err != nil || views >= maxViews {
		jsonError(w, "Secret not found or expired", 404)
		return
	}

	jsonResp(w, 200, map[string]any{
		"has_password":    pwdHash.Valid,
		"remaining_views": maxViews - views,
		"expires_at":      expiresAt,
	})
}

func jsonResp(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"detail":%s}`, strconv.Quote(msg))
}
