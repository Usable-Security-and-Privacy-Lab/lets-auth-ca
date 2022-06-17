package errorHandler

import (
	"os"

	"github.com/rs/zerolog/log"
)

func Fatal(err error) {
	log.Fatal().Err(err).Msg("A fatal error has occurred")
	os.Exit(2)
}
