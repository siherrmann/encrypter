package main

import (
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/siherrmann/encrypter"
)

func Server(port string) {
	e := echo.New()

	// Wrap with encryption middleware
	e.POST("/getData", echo.WrapHandler(encrypter.EncryptionMiddleware(http.HandlerFunc(DataHandler))))

	err := e.Start(":" + port)
	if err != nil {
		panic(err)
	}
}

func DataHandler(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Hallo Marius, das ist eine geheime Nachricht vom Server!"))
}
