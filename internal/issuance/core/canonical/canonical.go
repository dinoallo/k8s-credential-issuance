// Package canonical implements the JSON Canonicalization Scheme subset used by
// issuance/v1. It rejects duplicate keys and trailing JSON values before
// encoding deterministic UTF-8 JSON.
package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

func Parse(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := parseValue(decoder)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("trailing JSON data: %w", err)
		}
		return nil, fmt.Errorf("trailing JSON value %v", token)
	}
	return value, nil
}

func Canonicalize(data []byte) ([]byte, error) {
	value, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return Encode(value)
}

func Marshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

func Encode(value any) ([]byte, error) {
	var out strings.Builder
	if err := encode(&out, value); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

func parseValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate JSON object key %q", key)
				}
				item, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				object[key] = item
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("unterminated JSON object")
			}
			return object, nil
		case '[':
			var array []any
			for decoder.More() {
				item, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("unterminated JSON array")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter %q", value)
		}
	case string, bool, nil, json.Number:
		return value, nil
	default:
		return nil, fmt.Errorf("unsupported JSON token %T", token)
	}
}

func encode(out *strings.Builder, value any) error {
	switch value := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		encoded, err := quote(value)
		if err != nil {
			return err
		}
		out.WriteString(encoded)
	case json.Number:
		number, err := canonicalNumber(value.String())
		if err != nil {
			return err
		}
		out.WriteString(number)
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := encode(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			encoded, err := quote(key)
			if err != nil {
				return err
			}
			out.WriteString(encoded)
			out.WriteByte(':')
			if err := encode(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
	return nil
}

func quote(value string) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buffer.String(), "\n"), nil
}

func canonicalNumber(raw string) (string, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		return "", fmt.Errorf("number is outside the JCS IEEE-754 range: %q", raw)
	}
	if value == 0 {
		return "0", nil
	}
	abs := math.Abs(value)
	var formatted string
	if abs >= 1e-6 && abs < 1e21 {
		formatted = strconv.FormatFloat(value, 'f', -1, 64)
	} else {
		formatted = strconv.FormatFloat(value, 'e', -1, 64)
		formatted = normalizeExponent(formatted)
	}
	return formatted, nil
}

func normalizeExponent(value string) string {
	parts := strings.SplitN(value, "e", 2)
	if len(parts) != 2 {
		return value
	}
	exponent := parts[1]
	sign := ""
	if strings.HasPrefix(exponent, "+") || strings.HasPrefix(exponent, "-") {
		sign = exponent[:1]
		exponent = exponent[1:]
	}
	exponent = strings.TrimLeft(exponent, "0")
	if exponent == "" {
		exponent = "0"
	}
	return parts[0] + "e" + sign + exponent
}

func utf16Less(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	for i := 0; i < len(leftUnits) && i < len(rightUnits); i++ {
		if leftUnits[i] != rightUnits[i] {
			return leftUnits[i] < rightUnits[i]
		}
	}
	return len(leftUnits) < len(rightUnits)
}
