// Command clawpatrol-plugin-aws is the entry point for the AWS IAM Identity
// Center (SSO) clawpatrol gateway plugin. It wires the plugin declaration and
// hands it to the SDK's Run, which starts the go-plugin gRPC server the
// gateway connects to.
package main

import (
	"github.com/akefirad/clawpatrol-plugin-aws/internal/plugin"
	"github.com/denoland/clawpatrol/pluginsdk"
)

func main() {
	pluginsdk.Run(plugin.New())
}
