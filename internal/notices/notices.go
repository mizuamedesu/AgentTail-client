// Package notices preserves third-party license texts inside the executable.
package notices

import _ "embed"

//go:embed native.txt
var Text string
