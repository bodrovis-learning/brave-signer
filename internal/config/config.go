package config

import (
	"errors"
	"fmt"
	"strings"

	"brave-signer/internal/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GlobalConfig defines the shared configuration options.
type GlobalConfig struct {
	ConfigFileName string `mapstructure:"config-file-name"`
	ConfigFileType string `mapstructure:"config-file-type"`
	ConfigPath     string `mapstructure:"config-path"`
}

// Conf holds the Viper instance after loading the config.
var Conf *viper.Viper

// GlobalCfg is the parsed, typed global configuration.
var GlobalCfg GlobalConfig

// LoadConfig loads configuration from CLI flags, env vars, and an optional config file.
func LoadConfig(cmd *cobra.Command) error {
	v := viper.New()

	v.SetEnvPrefix("brave-signer")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	rootCmd := cmd.Root()

	if err := bindRootFlags(v, rootCmd); err != nil {
		return err
	}

	configFileName := v.GetString("config-file-name")
	configFileType := v.GetString("config-file-type")
	configPath := v.GetString("config-path")

	v.SetConfigName(configFileName)
	v.SetConfigType(configFileType)
	v.AddConfigPath(configPath)

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			logger.Info("Config file not found, using CLI values, env vars, and defaults.")
		} else {
			return fmt.Errorf("read config file: %w", err)
		}
	}

	if err := bindCommandFlags(v, cmd); err != nil {
		return err
	}

	if err := UnmarshalWith(v, &GlobalCfg); err != nil {
		return fmt.Errorf("unmarshal global config: %w", err)
	}

	Conf = v

	return nil
}

// Unmarshal unmarshals the loaded config into target.
func Unmarshal(target any) error {
	if Conf == nil {
		return errors.New("config is not loaded")
	}

	if err := UnmarshalWith(Conf, target); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}

	return nil
}

func UnmarshalWith(v *viper.Viper, target any) error {
	if err := v.Unmarshal(target); err != nil {
		return err
	}

	return nil
}

func bindRootFlags(v *viper.Viper, rootCmd *cobra.Command) error {
	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		return fmt.Errorf("bind root persistent flags: %w", err)
	}

	return nil
}

func bindCommandFlags(v *viper.Viper, cmd *cobra.Command) error {
	for currentCmd := cmd; currentCmd != nil; currentCmd = currentCmd.Parent() {
		if err := v.BindPFlags(currentCmd.PersistentFlags()); err != nil {
			return fmt.Errorf("bind persistent flags for %q: %w", currentCmd.Name(), err)
		}

		if err := v.BindPFlags(currentCmd.LocalFlags()); err != nil {
			return fmt.Errorf("bind local flags for %q: %w", currentCmd.Name(), err)
		}
	}

	return nil
}
