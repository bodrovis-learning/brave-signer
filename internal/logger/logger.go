package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	errorLogger = log.New(os.Stderr, "ERROR: ", 0)
	warnLogger  = log.New(os.Stdout, "WARN: ", 0)
	infoLogger  = log.New(os.Stdout, "INFO: ", 0)
)

// HaltOnErr logs an error and exits if the error is non-nil.
// Prefer returning errors from packages and commands; use this only at the app boundary.
func HaltOnErr(err error, messages ...string) {
	if err == nil {
		return
	}

	Error(err, messages...)
	os.Exit(1)
}

// Error logs an error.
func Error(err error, messages ...string) {
	if err == nil {
		return
	}

	message := joinMessage("An error occurred", messages...)
	errorLogger.Printf("%s: %v", message, err)
}

// Info logs an informational message.
func Info(message string) {
	infoLogger.Println(message)
}

// Warn logs a warning message.
func Warn(message string) {
	warnLogger.Println(message)
}

// WarnErr logs a warning message with an error.
func WarnErr(err error, messages ...string) {
	if err == nil {
		return
	}

	message := joinMessage("A warning occurred", messages...)
	warnLogger.Printf("%s: %v", message, err)
}

func joinMessage(defaultMessage string, messages ...string) string {
	if len(messages) == 0 {
		return defaultMessage
	}

	return fmt.Sprintf("%s: %s", defaultMessage, strings.Join(messages, " "))
}
