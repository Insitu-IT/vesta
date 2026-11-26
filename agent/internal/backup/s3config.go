package backup

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseS3Config normalizes the heartbeat S3 contract into the form expected by
// minio-go. Both backup providers use this function so a heartbeat cannot mean
// different things depending on which provider receives it.
func ParseS3Config(raw map[string]interface{}) (*S3Config, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	stringField := func(name string) (string, error) {
		value, present := raw[name]
		if !present || value == nil {
			return "", nil
		}
		text, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("S3 config %s must be a string", name)
		}
		return strings.TrimSpace(text), nil
	}
	boolField := func(name string) (bool, bool, error) {
		value, present := raw[name]
		if !present || value == nil {
			return false, false, nil
		}
		flag, ok := value.(bool)
		if !ok {
			return false, false, fmt.Errorf("S3 config %s must be a boolean", name)
		}
		return flag, true, nil
	}

	endpoint, err := stringField("endpoint")
	if err != nil {
		return nil, err
	}
	bucket, err := stringField("bucket")
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		return nil, fmt.Errorf("S3 config endpoint is required")
	}
	if bucket == "" {
		return nil, fmt.Errorf("S3 config bucket is required")
	}

	useSSL, sslPresent, err := boolField("use_ssl")
	if err != nil {
		return nil, err
	}
	normalizedEndpoint, inferredSSL, hasScheme, err := normalizeS3Endpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if hasScheme {
		if sslPresent && useSSL != inferredSSL {
			return nil, fmt.Errorf("S3 config endpoint scheme conflicts with use_ssl=%t", useSSL)
		}
		useSSL = inferredSSL
	}

	cfg := &S3Config{Endpoint: normalizedEndpoint, Bucket: bucket, UseSSL: useSSL}
	if cfg.Region, err = stringField("region"); err != nil {
		return nil, err
	}
	if cfg.AccessKey, err = stringField("access_key"); err != nil {
		return nil, err
	}
	if cfg.SecretKey, err = stringField("secret_key"); err != nil {
		return nil, err
	}
	if cfg.Prefix, err = stringField("prefix"); err != nil {
		return nil, err
	}
	if cfg.DeleteLocal, _, err = boolField("delete_local"); err != nil {
		return nil, err
	}
	return cfg, nil
}

func normalizeS3Endpoint(endpoint string) (host string, useSSL, hasScheme bool, err error) {
	value := endpoint
	if !strings.Contains(value, "://") {
		value = "//" + value
	} else {
		hasScheme = true
	}
	u, parseErr := url.Parse(value)
	if parseErr != nil {
		return "", false, false, fmt.Errorf("invalid S3 endpoint: %w", parseErr)
	}
	if hasScheme {
		switch strings.ToLower(u.Scheme) {
		case "https":
			useSSL = true
		case "http":
			useSSL = false
		default:
			return "", false, true, fmt.Errorf("S3 endpoint scheme must be http or https")
		}
	}
	if u.Host == "" || u.User != nil {
		return "", false, hasScheme, fmt.Errorf("S3 endpoint must contain a host without user information")
	}
	if u.Path != "" && u.Path != "/" {
		return "", false, hasScheme, fmt.Errorf("S3 endpoint must not contain a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", false, hasScheme, fmt.Errorf("S3 endpoint must not contain a query or fragment")
	}
	return u.Host, useSSL, hasScheme, nil
}
