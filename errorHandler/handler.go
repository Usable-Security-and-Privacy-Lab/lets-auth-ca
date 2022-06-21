package errorHandler

import (
	"os"

	"github.com/rs/zerolog/log"
)

// Fatal will automatically exit the calling program, logging the given error.
func Fatal(err error) {
	log.Fatal().Err(err).Msg("A fatal error has occurred")
	os.Exit(2)
}
