package xds

import (
	"github.com/sirupsen/logrus"
)

var log logrus.FieldLogger
var config *Config

// Init initializes the base resources.
func Init(logger *logrus.Logger, c *Config) {
	log = logger.WithField("package", "xds")
	config = c
	log.Infof("Base config: %+v", config)
}

// GetConfig returns the current config.
func GetConfig() *Config {
	return config
}