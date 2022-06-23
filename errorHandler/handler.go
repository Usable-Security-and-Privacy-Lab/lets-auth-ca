package errorHandler

// We should probably look into using a logger. See here for suggestions:
// https://github.com/sirupsen/logrus

import (
	"os"

	"github.com/rs/zerolog/log"
)

// Fatal will automatically exit the calling program, logging the given error.
func Fatal(err error) {
	log.Fatal().Err(err).Msg("A fatal error has occurred")
	os.Exit(2)
}
