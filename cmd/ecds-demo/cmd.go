package cmd

import (
	"strings"

	"github.com/bladedancer/ecds-demo/pkg/xds"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// RootCmd configures the command params for the main line.
var RootCmd = &cobra.Command{
	Use:     "ecdsdemo",
	Short:   "Test ECDS.",
	Version: "0.0.1",
	RunE:    run,
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.Flags().Uint32("port", 10000, "The XDS GRPC port.")
	RootCmd.Flags().String("logLevel", "info", "log level")
	RootCmd.Flags().String("logFormat", "json", "line or json")

	bindOrPanic("port", RootCmd.Flags().Lookup("port"))
	bindOrPanic("log.level", RootCmd.Flags().Lookup("logLevel"))
	bindOrPanic("log.format", RootCmd.Flags().Lookup("logFormat"))
}

func initConfig() {
	viper.SetTypeByDefaultValue(true)
	viper.SetEnvPrefix("xds")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
}

func bindOrPanic(key string, flag *flag.Flag) {
	if err := viper.BindPFlag(key, flag); err != nil {
		panic(err)
	}
}

func run(cmd *cobra.Command, args []string) error {
	logger, err := setupLogging(viper.GetString("log.level"), viper.GetString("log.format"))
	if err != nil {
		return err
	}

	xds.Init(logger, xdsConfig())
	return xds.Run()
}

func xdsConfig() *xds.Config {
	return &xds.Config{
		Port: viper.GetUint32("port"),
	}
}