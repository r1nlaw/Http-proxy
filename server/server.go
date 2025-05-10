package main

import (
	"fmt"
	"log"
	"net/http"
)

// Обработчик для загрузки файла index.html
func handler(w http.ResponseWriter, r *http.Request) {
	// Устанавливаем CORS заголовки для всех запросов
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Обслуживаем файл index.html
	http.ServeFile(w, r, "index.html")
}

func main() {
	// Регистрируем обработчик
	http.HandleFunc("/", handler)

	// Запускаем сервер на порту 8085
	port := "8085"
	fmt.Printf("Starting server on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
