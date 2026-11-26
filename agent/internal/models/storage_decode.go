package models

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const MaxStorageRequestBytes = 4 * 1024 * 1024

var ErrStorageRequest = errors.New("unsupported or malformed storage transaction")

// DecodeStorageControlJSONBounded checks a bounded control envelope before its
// operation-specific decoder. Unlike DecodeStorageValue it permits nested raw
// JSON documents; it does not waive the caller's field or authority validation.
func DecodeStorageControlJSONBounded(data []byte, limit int) (map[string]any, error) {
	if limit <= 0 || limit > 64<<20 || len(data) > limit || !storageUnicode(data) {
		return nil, ErrStorageRequest
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := strictValueBound(d, 0, 10000)
	if err != nil {
		return nil, ErrStorageRequest
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrStorageRequest
	}
	object, ok := v.(map[string]any)
	if !ok {
		return nil, ErrStorageRequest
	}
	return object, nil
}

// DecodeStorageControlJSON shares the duplicate/depth/size refusal boundary.
// The caller still validates the exact operation-specific response schema.
func DecodeStorageControlJSON(data []byte) (map[string]any, error) {
	if len(data) > 1<<20 {
		return nil, ErrStorageRequest
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := strictValue(d, 0)
	if err != nil {
		return nil, ErrStorageRequest
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrStorageRequest
	}
	result, ok := v.(map[string]any)
	if !ok {
		return nil, ErrStorageRequest
	}
	return result, nil
}

// strictValue rejects duplicate keys instead of accepting the last value. This
// is wire parsing only, never upload or publication authority.
func strictValue(d *json.Decoder, depth int) (any, error) {
	return strictValueBound(d, depth, 4096)
}

func strictValueBound(d *json.Decoder, depth, maxItems int) (any, error) {
	if depth > 32 {
		return nil, ErrStorageRequest
	}
	token, err := d.Token()
	if err != nil {
		return nil, ErrStorageRequest
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delim {
	case '{':
		value := map[string]any{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, ErrStorageRequest
			}
			if _, exists := value[name]; exists {
				return nil, ErrStorageRequest
			}
			item, err := strictValueBound(d, depth+1, maxItems)
			if err != nil {
				return nil, err
			}
			value[name] = item
		}
		if _, err = d.Token(); err != nil {
			return nil, ErrStorageRequest
		}
		return value, nil
	case '[':
		value := []any{}
		for d.More() {
			if len(value) >= maxItems {
				return nil, ErrStorageRequest
			}
			item, err := strictValueBound(d, depth+1, maxItems)
			if err != nil {
				return nil, err
			}
			value = append(value, item)
		}
		if _, err = d.Token(); err != nil {
			return nil, ErrStorageRequest
		}
		return value, nil
	default:
		return nil, ErrStorageRequest
	}
}

// Every declared field is required, including explicitly nullable pointer
// fields. JSON null is not an omitted/empty object, array, string or count.
func exactShape(value any, kind reflect.Type) bool {
	if kind.Kind() == reflect.Pointer {
		return value == nil || exactShape(value, kind.Elem())
	}
	switch kind.Kind() {
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok || kind.Key().Kind() != reflect.String {
			return false
		}
		for _, item := range object {
			if !exactShape(item, kind.Elem()) {
				return false
			}
		}
		return true
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		expected := kind.NumField()
		// This one negotiated extension is optional only when absent. Do not
		// relax required/null semantics for other fields or wire envelopes.
		if kind == reflect.TypeOf(StorageTransactionPlan{}) {
			profile, present := object["transfer_profile"]
			if !present {
				expected--
			} else if profile != KubevirtTransfer32 {
				return false
			}
		}
		if kind == reflect.TypeOf(StorageSource{}) {
			schema, ok := object["schema"].(json.Number)
			if !ok {
				return false
			}
			switch schema.String() {
			case "1":
				if _, present := object["native_volumes"]; present {
					return false
				}
				expected--
			case "2":
				if _, present := object["native_volumes"]; !present {
					return false
				}
			default:
				return false
			}
		}
		if len(object) != expected {
			return false
		}
		for i := 0; i < kind.NumField(); i++ {
			field := kind.Field(i)
			item, exists := object[strings.Split(field.Tag.Get("json"), ",")[0]]
			if !exists && kind == reflect.TypeOf(StorageTransactionPlan{}) && field.Name == "TransferProfile" {
				continue
			}
			if !exists && kind == reflect.TypeOf(StorageSource{}) && field.Name == "NativeVolumes" {
				continue
			}
			if !exists || !exactShape(item, field.Type) {
				return false
			}
		}
		return true
	case reflect.Slice:
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range array {
			if !exactShape(item, kind.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := value.(string)
		return ok
	case reflect.Bool:
		_, ok := value.(bool)
		return ok
	case reflect.Int, reflect.Int64:
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := number.Int64()
		return err == nil
	case reflect.Uint64:
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := strconv.ParseUint(string(number), 10, 64)
		return err == nil
	default:
		return false
	}
}

func DecodeStorageTransaction(body []byte) (*StorageTransactionRequest, error) {
	if len(body) > MaxStorageRequestBytes || !storageUnicode(body) {
		return nil, ErrStorageRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	value, err := strictValue(decoder, 0)
	if err != nil {
		return nil, ErrStorageRequest
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrStorageRequest
	}
	if !exactShape(value, reflect.TypeOf(StorageTransactionRequest{})) {
		return nil, ErrStorageRequest
	}
	var request StorageTransactionRequest
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, ErrStorageRequest
	}
	if request.Protocol != StorageProtocol || (request.Plan.Source.Schema != 1 && request.Plan.Source.Schema != 2) ||
		!slices.Contains(StorageProfiles(), request.Plan.CapabilityProfile) ||
		request.Plan.Provider != "kubevirt" {
		return nil, ErrStorageRequest
	}
	digest, err := storagePlanDigest(value.(map[string]any)["plan"])
	if err != nil || subtle.ConstantTimeCompare([]byte(digest), []byte(request.PlanSHA256)) != 1 {
		return nil, ErrStorageRequest
	}
	if !validStorageSemantics(&request) {
		return nil, ErrStorageRequest
	}
	return &request, nil
}
