package backup

import (
	"strings"
	"testing"
)

func TestParseS3ConfigNormalizesHeartbeatContract(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]interface{}
		host string
		ssl  bool
	}{
		{"https URL", map[string]interface{}{"endpoint": "https://s3.example.com", "bucket": "backups"}, "s3.example.com", true},
		{"http URL", map[string]interface{}{"endpoint": "http://s3.example.com:9000/", "bucket": "backups"}, "s3.example.com:9000", false},
		{"bare TLS host", map[string]interface{}{"endpoint": "s3.example.com:9000", "bucket": "backups", "use_ssl": true}, "s3.example.com:9000", true},
		{"bare plain host", map[string]interface{}{"endpoint": "s3.example.com:9000", "bucket": "backups", "use_ssl": false}, "s3.example.com:9000", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.raw["region"] = "eu-1"
			tt.raw["access_key"] = "access"
			tt.raw["secret_key"] = "secret"
			tt.raw["prefix"] = "vm/backups"
			tt.raw["delete_local"] = true
			cfg, err := ParseS3Config(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Endpoint != tt.host || cfg.UseSSL != tt.ssl || cfg.Bucket != "backups" || cfg.Region != "eu-1" || cfg.AccessKey != "access" || cfg.SecretKey != "secret" || cfg.Prefix != "vm/backups" || !cfg.DeleteLocal {
				t.Fatalf("unexpected config: %#v", cfg)
			}
		})
	}
}

func TestParseS3ConfigRejectsInvalidOrAmbiguousEndpoints(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]interface{}
		want string
	}{
		{"missing host", map[string]interface{}{"endpoint": "https://", "bucket": "b"}, "host"},
		{"endpoint path", map[string]interface{}{"endpoint": "https://s3.example.com/storage", "bucket": "b"}, "path"},
		{"endpoint query", map[string]interface{}{"endpoint": "https://s3.example.com?region=x", "bucket": "b"}, "query"},
		{"bare path", map[string]interface{}{"endpoint": "s3.example.com/storage", "bucket": "b"}, "path"},
		{"TLS conflict", map[string]interface{}{"endpoint": "https://s3.example.com", "bucket": "b", "use_ssl": false}, "conflicts"},
		{"plain conflict", map[string]interface{}{"endpoint": "http://s3.example.com", "bucket": "b", "use_ssl": true}, "conflicts"},
		{"missing bucket", map[string]interface{}{"endpoint": "s3.example.com"}, "bucket"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseS3Config(tt.raw)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
