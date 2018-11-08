package main

import (
	"fmt"
	"net/http"

	"github.com/finkf/pcwgo/api"
)

func notFound(format string, args ...interface{}) api.ErrorResponse {
	return api.NewErrorResponse(
		http.StatusNotFound,
		fmt.Sprintf(format, args...),
	)
}

func badRequest(format string, args ...interface{}) api.ErrorResponse {
	return api.NewErrorResponse(
		http.StatusBadRequest,
		fmt.Sprintf(format, args...),
	)
}

func forbidden(format string, args ...interface{}) api.ErrorResponse {
	return api.NewErrorResponse(
		http.StatusForbidden,
		fmt.Sprintf(format, args...),
	)
}

func methodNotAllowed(format string, args ...interface{}) api.ErrorResponse {
	return api.NewErrorResponse(
		http.StatusMethodNotAllowed,
		fmt.Sprintf(format, args...),
	)
}

func internalServerError(format string, args ...interface{}) api.ErrorResponse {
	return api.NewErrorResponse(
		http.StatusInternalServerError,
		fmt.Sprintf(format, args...),
	)
}

func errorFromCode(code int, format string, args ...interface{}) api.ErrorResponse {
	return api.NewErrorResponse(
		code,
		fmt.Sprintf(format, args...),
	)
}
