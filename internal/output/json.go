package output

import (
	"encoding/json"
	"io"

	"github.com/11lunaric11/securitychecker/internal/model"
)

// RenderJSON writes the results as an indented JSON array.
func RenderJSON(w io.Writer, results []model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(results)
}
