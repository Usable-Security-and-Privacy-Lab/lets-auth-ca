package util

import (
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func SetUpLogger(level int, path string) {
	// Set up Logging
	switch level {
	case -1:
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case 0:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case 1:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case 2:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case 3:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case 4:
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case 5:
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	}

	var dest *os.File
	if path == "" {
		dest = os.Stdout
	} else if path == "config" {
		var err error
		// TODO: Should the logger be set up before or after the config file?
		// If before, we could set the location of the log output in the file
		// If after, we could use the logger in error handler and the config file
		date := time.Now().Format("01-02-2006")
		dest, err = os.Open(date + ".log")
		if err != nil {
			panic(err)
		}
	} else {
		var err error
		date := time.Now().Format("01-02-2006")
		dest, err = os.Open(date + ".log")
		if err != nil {
			panic(err)
		}
	}
	output := zerolog.ConsoleWriter{Out: dest, TimeFormat: time.RFC3339}
	output.FormatFieldName = func(i interface{}) string {
		return fmt.Sprintf("\n\t%s:", i)
	}
	log.Logger = log.Output(output)

	log.Info().Msg("Logger set up.")
}

func LogTest() {
	log.Trace().Msg("Logging Level: Trace")
	log.Debug().Msg("Logging Level: Debug")
	log.Info().Msg("Logging Level: Info")
	log.Warn().Msg("Logging Level: Warn")
	log.Error().Msg("Logging Level: Error")
	log.Fatal().Msg("Logging Level: Fatal")
	log.Panic().Msg("Logging Level: Panic")
}
