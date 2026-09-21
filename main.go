package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

var (
	antilopayPrivateKey       string
	antilopayPublicKey        string
	antilopaySecretId         string
	antilopaySteamShopId      string
	antilopayPayoutPrivateKey string
)

const antilopayBaseURL = "https://lk.antilopay.com/api/v1"

var antilopayClient = &http.Client{
	Timeout: 15 * time.Second,
}

// Хранилище связки order_id -> steam_account и суммы зачисления
var ordersSync sync.Map

type PendingOrder struct {
	SteamAccount string
	TopupAmount  float64
}

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("Файл .env не найден, используются системные переменные")
	}

	antilopayPrivateKey = os.Getenv("ANTILOPAY_PRIVATE_KEY")
	antilopayPublicKey = os.Getenv("ANTILOPAY_STEAM_PUBLIC_KEY")
	antilopaySecretId = os.Getenv("ANTILOPAY_SECRET_ID")
	antilopaySteamShopId = os.Getenv("ANTILOPAY_STEAM_SHOP_ID")
	antilopayPayoutPrivateKey = os.Getenv("ANTILOPAY_PAYOUT_PRIVATE_KEY")
}

// === КРИПТОГРАФИЯ ===

func loadPrivateKey(rawKey string) (*rsa.PrivateKey, error) {
	raw := strings.TrimSpace(rawKey)
	if raw == "" {
		return nil, errors.New("ключ пуст")
	}

	var keyBytes []byte
	if strings.HasPrefix(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		keyBytes = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, err
		}
		keyBytes = decoded
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return privateKey, nil
}

func loadPublicKey(rawKey string) (*rsa.PublicKey, error) {
	raw := strings.TrimSpace(rawKey)
	if raw == "" {
		return nil, errors.New("публичный ключ пуст")
	}

	var keyBytes []byte
	if strings.HasPrefix(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		keyBytes = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, err
		}
		keyBytes = decoded
	}

	parsedKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX: %w", err)
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return publicKey, nil
}

func sign(payload []byte, rawKey string) (string, error) {
	rsaKey, err := loadPrivateKey(rawKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func verifySignature(payload []byte, signatureBase64 string) error {
	pubKey, err := loadPublicKey(antilopayPublicKey)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	hash := sha256.Sum256(payload)
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes)
}

func setHeaders(req *http.Request, signature string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Apay-Secret-Id", antilopaySecretId)
	req.Header.Set("X-Apay-Sign", signature)
	req.Header.Set("X-Apay-Sign-Version", "1")
}

// === ANTILOPAY API МЕТОДЫ ===

func CheckSteamAccount(steamAccount string) error {
	body := map[string]string{
		"project_identificator": antilopaySteamShopId,
		"steam_account":         steamAccount,
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, antilopayBaseURL+"/steam/account/check", bytes.NewReader(payload))
	if err != nil {
		return err
	}

	// Проверка аккаунта подписывается ОСНОВНЫМ ключом
	signature, err := sign(payload, antilopayPrivateKey)
	if err != nil {
		return fmt.Errorf("sign error: %w", err)
	}
	setHeaders(req, signature)

	resp, err := antilopayClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("check failed (status %d): %s", resp.StatusCode, bodyBytes)
}

func CreateCustomerPayment(orderId string, amountPaid int, description string) (string, error) {
	body := map[string]interface{}{
		"project_identificator": antilopaySteamShopId,
		"amount":                amountPaid,
		"order_id":              orderId,
		"currency":              "RUB",
		"product_name":          "Пополнение Steam",
		"product_type":          "services",
		"description":           description,
		"customer": map[string]string{
			"email": "customer@refka.fun",
		},
		"success_url": "https://refka.fun/success",
		"fail_url":    "https://refka.fun/cancel",
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, antilopayBaseURL+"/payment/create", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}

	// Создание клиентского платежа подписывается ОСНОВНЫМ ключом
	signature, err := sign(payload, antilopayPrivateKey)
	if err != nil {
		return "", fmt.Errorf("sign error: %w", err)
	}
	setHeaders(req, signature)

	resp, err := antilopayClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return "", err
	}

	if code, ok := result["code"].(float64); ok && code != 0 {
		return "", fmt.Errorf("gateway error: %v", result["error"])
	}

	paymentUrl, ok := result["payment_url"].(string)
	if !ok {
		return "", fmt.Errorf("no payment_url in response: %s", bodyBytes)
	}

	return paymentUrl, nil
}

func ExecuteSteamPayout(orderId string, amount float64, steamAccount string) error {
	body := map[string]interface{}{
		"project_identificator": antilopaySteamShopId,
		"order_id":              orderId,
		"amount":                amount,
		"method":                "STEAM",
		"account":               steamAccount,
		"comment":               "Refka Steam Topup",
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, antilopayBaseURL+"/withdraw/create", bytes.NewReader(payload))
	if err != nil {
		return err
	}

	// ВЫПЛАТА на Steam подписывается КЛЮЧОМ ВЫПЛАТ
	signature, err := sign(payload, antilopayPayoutPrivateKey)
	if err != nil {
		return fmt.Errorf("sign error: %w", err)
	}
	setHeaders(req, signature)

	resp, err := antilopayClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return err
	}

	if code, ok := result["code"].(float64); ok && code != 0 {
		return fmt.Errorf("withdraw error: %v", result["error"])
	}

	log.Printf("🎉 Средства успешно отправлены в Steam! Withdraw ID: %v", result["withdraw_id"])
	return nil
}

// === ОБРАБОТЧИКИ САЙТА ===

func calculateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		return
	}

	var req struct {
		Region    string  `json:"region"`
		AmountRub float64 `json:"amount_rub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	rates := map[string]float64{
		"steam_ru": 1.0,  // Рубли
		"steam_kz": 5.30, // Тенге (1 RUB ≈ 5.30 KZT)
		"steam_ua": 0.53, // Гривны (1 RUB ≈ 0.53 UAH)
		// Остальные СНГ-регионы Steam конвертируются через USD (1 USD ≈ 84.10 RUB)
		"steam_by": 0.0119,
		"steam_kg": 0.0119,
		"steam_am": 0.0119,
		"steam_tj": 0.0119,
		"steam_uz": 0.0119,
		"steam_az": 0.0119,
		"steam_md": 0.0119,
	}

	rate, ok := rates[req.Region]
	if !ok {
		http.Error(w, `{"error": "Invalid region"}`, http.StatusBadRequest)
		return
	}

	w.Write([]byte(fmt.Sprintf(`{"amount": "%.2f"}`, req.AmountRub*rate)))
}

func topupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		return
	}

	var req struct {
		Region    string  `json:"region"`
		AmountRub float64 `json:"amount_rub"`
		Account   string  `json:"account"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Неверный формат запроса"})
		return
	}

	if req.AmountRub < 50 {
		json.NewEncoder(w).Encode(map[string]string{"error": "Минимальная сумма 50 рублей"})
		return
	}
	if req.Account == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Укажите логин Steam"})
		return
	}

	if err := CheckSteamAccount(req.Account); err != nil {
		log.Printf("Ошибка CheckSteamAccount: %v", err)
		json.NewEncoder(w).Encode(map[string]string{"error": "Steam аккаунт не найден или закрыт для пополнений"})
		return
	}

	var markup float64

	if req.AmountRub < 500 {
		markup = 1.08 // 8% для мелких платежей
	} else if req.AmountRub < 2000 {
		markup = 1.06 // 6% для средних платежей
	} else {
		markup = 1.04 // 4% для крупных платежей
	}

	payAmount := int(math.Round(req.AmountRub * markup))

	orderId := fmt.Sprintf("pay_%d", time.Now().UnixNano())

	ordersSync.Store(orderId, PendingOrder{
		SteamAccount: req.Account,
		TopupAmount:  req.AmountRub,
	})

	paymentUrl, err := CreateCustomerPayment(orderId, payAmount, fmt.Sprintf("Пополнение Steam для %s", req.Account))
	if err != nil {
		log.Printf("Ошибка CreateCustomerPayment: %v", err)
		json.NewEncoder(w).Encode(map[string]string{"error": "Не удалось создать платеж. Попробуйте позже."})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"payment_url": paymentUrl})
}

// === ВЕБХУК ОПЛАТЫ ===

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Cannot read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	signature := r.Header.Get("X-Apay-Sign")
	if signature != "" {
		if err := verifySignature(bodyBytes, signature); err != nil {
			log.Printf("Внимание: ошибка проверки подписи вебхука: %v", err)
			http.Error(w, "Invalid signature", http.StatusForbidden)
			return
		}
	}

	var payload struct {
		Status  string `json:"status"`
		OrderId string `json:"order_id"`
	}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		http.Error(w, "Bad JSON", http.StatusBadRequest)
		return
	}

	if payload.Status == "SUCCESS" {
		log.Printf("Оплата заказа %s подтверждена!", payload.OrderId)

		if val, ok := ordersSync.Load(payload.OrderId); ok {
			order := val.(PendingOrder)
			log.Printf("🚀 Отправляем %v RUB на аккаунт %s...", order.TopupAmount, order.SteamAccount)

			payoutOrderId := fmt.Sprintf("payout_%s", payload.OrderId)
			if err := ExecuteSteamPayout(payoutOrderId, order.TopupAmount, order.SteamAccount); err != nil {
				log.Printf("Ошибка отправки на Steam: %v", err)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	http.HandleFunc("/api/calculate", calculateHandler)
	http.HandleFunc("/api/topup", topupHandler)
	http.HandleFunc("/api/callback", callbackHandler)

	port := ":8080"
	log.Printf("Сервер запущен на порту %s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Ошибка запуска: %v", err)
	}
}
