package models

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"unicode/utf8"
)

// encoding/json replaces unpaired surrogate escapes with U+FFFD. Python's
// UTF-8 digest cannot encode those inputs, so reject rather than silently
// signing a different plan. Escaped backslashes are not Unicode escapes.
func storageUnicode(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			continue
		}
		i++
		if i >= len(body) || body[i] != 'u' {
			continue
		}
		if i+4 >= len(body) {
			return false
		}
		n, err := strconv.ParseUint(string(body[i+1:i+5]), 16, 16)
		if err != nil || n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		i += 4
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(body) || body[i+1] != '\\' || body[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(body[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// canonicalStorageJSON matches Python sort_keys=True, separators=(",", ":"),
// ensure_ascii=False for the transaction's string/null/integer/container types.
// In particular HTML and U+2028/U+2029 must not acquire Go's JSON escapes.
// Floats are deliberately unsupported: byte counts never pass through float64.
func canonicalStorageJSON(out *bytes.Buffer, value any) error {
	return canonicalJSON(out, value, false)
}

func canonicalJSON(out *bytes.Buffer, value any, booleans bool) error {
	switch v := value.(type) {
	case bool:
		if !booleans {
			return ErrStorageRequest
		}
		out.WriteString(strconv.FormatBool(v))
	case nil:
		out.WriteString("null")
	case string:
		if !utf8.ValidString(v) {
			return ErrStorageRequest
		}
		out.WriteByte('"')
		for _, r := range v {
			switch r {
			case '"', '\\':
				out.WriteByte('\\')
				out.WriteRune(r)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if r < 0x20 {
					out.WriteString(`\u00`)
					out.WriteByte("0123456789abcdef"[byte(r)>>4])
					out.WriteByte("0123456789abcdef"[byte(r)&15])
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			// Native inventory custody includes uint64 device/inode values.
			// Keep the original signed-only plan canonicalizer unchanged.
			if booleans {
				if unsigned, e := strconv.ParseUint(string(v), 10, 64); e == nil {
					out.WriteString(strconv.FormatUint(unsigned, 10))
					return nil
				}
			}
			return ErrStorageRequest
		}
		out.WriteString(strconv.FormatInt(n, 10))
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i != 0 {
				out.WriteByte(',')
			}
			if err := canonicalJSON(out, item, booleans); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i != 0 {
				out.WriteByte(',')
			}
			if err := canonicalJSON(out, key, booleans); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := canonicalJSON(out, v[key], booleans); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return ErrStorageRequest
	}
	return nil
}

func storagePlanDigest(plan any) (string, error) {
	var canonical bytes.Buffer
	if err := canonicalStorageJSON(&canonical, plan); err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(digest[:]), nil
}
