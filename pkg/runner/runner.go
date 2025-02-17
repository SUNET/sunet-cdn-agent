package runner

import (
	"github.com/rs/zerolog"
)

func Run(logger zerolog.Logger) error {
	logger.Info().Msg("agent runner")
	return nil
}
