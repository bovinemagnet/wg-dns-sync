package config

import "testing"

func TestValidateRequiresDNSNames(t *testing.T) {
	cfg := AppConfig{}
	cfg.ApplyDefaults()
	cfg.Output.Mode = "stdout"
	cfg.Output.Format = "plain"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for empty dns names")
	}
}
