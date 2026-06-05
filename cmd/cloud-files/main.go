package main

import (
	"fmt"
	"net/http"

	handlerv1 "github.com/kaynelza/cloud-files/internal/presentation/openapi/v1"
	apiv1 "github.com/kaynelza/cloud-files/pkg/openapi/v1"
)

func main() {
	handler := handlerv1.New()
	srv, err := apiv1.NewServer(handler, apiv1.WithMiddleware(handlerv1.Middleware))
	if err != nil {
		fmt.Println(err)
	}
	http.ListenAndServe(":8080", srv)
}
