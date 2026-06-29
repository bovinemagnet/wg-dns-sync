package output

import (
	"os"
	"strings"
)

func WriteText(path, text string) error {
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return os.WriteFile(path, []byte(text), 0o600)
}
