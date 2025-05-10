package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Цвета для логов
const (
	Red   = "\033[31m"
	Reset = "\033[0m"
)

func main() {
	fmt.Println("Proxy server listening on http://localhost:8080")
	http.ListenAndServe(":8080", http.HandlerFunc(handleRequest))
}

func handleRequest(w http.ResponseWriter, req *http.Request) {
	// Поддержка CORS запросов
	if req.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "x-test-injection, x-test-scanner, x-test-xss")
		w.WriteHeader(http.StatusOK)
		return
	}

	// 1. Логируем базовую информацию
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("New request from %s", req.RemoteAddr)
	log.Printf("Time: %s", time.Now().Format("2006-01-02 15:04:05"))
	log.Printf("Method: %s", req.Method)
	log.Printf("URL: %s", req.URL.String())
	log.Println("Headers:")

	// 2. Анализ заголовков
	var maliciousHeaderName string
	var maliciousHeaderValue string
	foundMalicious := false

	for name, values := range req.Header {
		for _, value := range values {
			if isSuspiciousHeader(name, value) {
				log.Printf("   %s: %s", Red+name+Reset, Red+value+Reset)
				maliciousHeaderName = name
				maliciousHeaderValue = value
				foundMalicious = true
			} else {
				log.Printf("   %s: %s", name, value)
			}
		}
	}

	if foundMalicious {
		log.Println("Suspicious header detected, request aborted.")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "x-test-injection, x-test-scanner, x-test-xss")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		errorMsg := fmt.Sprintf(`{"error": "Suspicious header detected", "header": "%s", "value": "%s"}`,
			maliciousHeaderName, maliciousHeaderValue)
		fmt.Fprint(w, errorMsg)
		return
	}

	// 3. Создаем новый запрос
	outReq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	outReq.Header = req.Header.Clone()

	// 4. Выполняем запрос
	client := &http.Client{}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, "Failed to reach target", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 5. Копируем ответ
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Проверка на вредоносные заголовки по значениям
func isSuspiciousHeader(name, value string) bool {
	// Список безопасных заголовков, которые не следует проверять
	safeHeaders := []string{
		"Accept", "User-Agent", "Content-Type", "Host", "Connection", "Upgrade-Insecure-Requests",
		"Accept-Encoding", "Accept-Language", "Sec-Fetch-Mode", "Cookie", "Proxy-Connection", "Sec-Fetch-Site", "Sec-Fetch-Dest", "Origin", "If-Modified-Since", "If-None-Match", "Priority", "Referer",
	}

	// Если это безопасный заголовок, игнорируем его
	for _, safeHeader := range safeHeaders {
		if name == safeHeader {
			return false
		}
	}

	// Примитивные сигнатуры XSS
	xssPatterns := []string{
		"<script", "javascript:", "onerror", "onload", "alert(", "<img", "<iframe", "' OR '1'='1",
	}

	// Примитивные сигнатуры SQL-инъекций
	sqlPatterns := []string{
		"' OR '1'='1", "\" OR \"1\"=\"1", "' AND '1'='1", "UNION SELECT", "--", ";--", "'--", "/*", "*/", "@@", "@",
		"char(", "nchar(", "varchar(", "alter table", "drop table", "insert into", "select * from", "sqlmap",
	}

	// Дополнительные регулярные выражения для более сложных инъекций
	// Пример: обнаружение командной инъекции
	commandInjectionPatterns := []string{
		"cmd=", "bash", "sh", "exec", "system", "input", "|", "&", ";", "`", ">", "<",
	}

	// Преобразуем значение в нижний регистр
	valueLower := strings.ToLower(value)

	// Проверка на наличие подозрительных шаблонов
	for _, pattern := range append(xssPatterns, sqlPatterns...) {
		if strings.Contains(valueLower, pattern) {
			log.Printf("Detected suspicious content in header %s: %s", name, value)
			return true
		}
	}

	// Проверка на командные инъекции через регулярные выражения
	for _, pattern := range commandInjectionPatterns {
		matched, _ := regexp.MatchString(pattern, valueLower)
		if matched {
			log.Printf("Detected command injection in header %s: %s", name, value)
			return true
		}
	}

	return false
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
