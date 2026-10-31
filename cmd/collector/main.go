package main

import (
	"context"

	_ "github.com/warpstreamlabs/bento/public/components/io"
	_ "github.com/warpstreamlabs/bento/public/components/kafka"
	_ "github.com/warpstreamlabs/bento/public/components/prometheus"
	_ "github.com/warpstreamlabs/bento/public/components/pure"
	"github.com/warpstreamlabs/bento/public/service"

	_ "github.com/HelixY2J/collector/internal/source/googleworkspace"
	_ "github.com/HelixY2J/collector/internal/source/okta"
)

var (
	version   = "dev"
	dateBuilt = "unknown"
)

func main() {
	service.RunCLI(context.Background(),
		service.CLIOptSetBinaryName("collector"),
		service.CLIOptSetVersion(version, dateBuilt),
	)
}
