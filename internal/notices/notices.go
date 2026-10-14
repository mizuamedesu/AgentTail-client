// SPDX-License-Identifier: GPL-3.0-or-later

// Package notices preserves third-party license texts inside the executable.
package notices

import _ "embed"

//go:embed native.txt
var Text string

//go:embed gpl.txt
var GPL string

const SourceURL = "https://github.com/mizuamedesu/AgentTail-client"
