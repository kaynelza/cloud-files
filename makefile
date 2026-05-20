generate-ogen:
	ogen --target pkg/openapi/v1 --clean api/openapi/openapi.yaml --config _ogen.yml

.PHONY: generate-ogen