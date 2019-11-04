// Copyright 2017 The github.com/go-ethereum-analysis Authors
// This file is part of github.com/go-ethereum-analysis.
//
// github.com/go-ethereum-analysis is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// github.com/go-ethereum-analysis is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with github.com/go-ethereum-analysis. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"unicode"

	cli "gopkg.in/urfave/cli.v1"

	"github.com/go-ethereum-analysis/cmd/utils"
	"github.com/go-ethereum-analysis/dashboard"
	"github.com/go-ethereum-analysis/eth"
	"github.com/go-ethereum-analysis/node"
	"github.com/go-ethereum-analysis/params"
	whisper "github.com/go-ethereum-analysis/whisper/whisperv6"
	"github.com/naoina/toml"
)

var (
	dumpConfigCommand = cli.Command{
		Action:      utils.MigrateFlags(dumpConfig),
		Name:        "dumpconfig",
		Usage:       "Show configuration values",
		ArgsUsage:   "",
		Flags:       append(append(nodeFlags, rpcFlags...), whisperFlags...),
		Category:    "MISCELLANEOUS COMMANDS",
		Description: `The dumpconfig command shows configuration values.`,
	}

	configFileFlag = cli.StringFlag{
		Name:  "config",
		Usage: "TOML configuration file",
	}
)

// These settings ensure that TOML keys use the same names as Go struct fields.
var tomlSettings = toml.Config{
	NormFieldName: func(rt reflect.Type, key string) string {
		return key
	},
	FieldToKey: func(rt reflect.Type, field string) string {
		return field
	},
	MissingField: func(rt reflect.Type, field string) error {
		link := ""
		if unicode.IsUpper(rune(rt.Name()[0])) && rt.PkgPath() != "main" {
			link = fmt.Sprintf(", see https://godoc.org/%s#%s for available fields", rt.PkgPath(), rt.Name())
		}
		return fmt.Errorf("field '%s' is not defined in %s%s", field, rt.String(), link)
	},
}

type ethstatsConfig struct {
	URL string `toml:",omitempty"`
}

type gethConfig struct {
	Eth       eth.Config
	Shh       whisper.Config
	Node      node.Config
	Ethstats  ethstatsConfig
	Dashboard dashboard.Config
}

func loadConfig(file string, cfg *gethConfig) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	err = tomlSettings.NewDecoder(bufio.NewReader(f)).Decode(cfg)
	// Add file name to errors that have a line number.
	if _, ok := err.(*toml.LineError); ok {
		err = errors.New(file + ", " + err.Error())
	}
	return err
}

// 获取节点的默认配置项
func defaultNodeConfig() node.Config {
	cfg := node.DefaultConfig
	cfg.Name = clientIdentifier
	cfg.Version = params.VersionWithCommit(gitCommit)
	cfg.HTTPModules = append(cfg.HTTPModules, "eth", "shh")
	cfg.WSModules = append(cfg.WSModules, "eth", "shh")
	cfg.IPCPath = "geth.ipc"
	return cfg
}

func makeConfigNode(ctx *cli.Context) (*node.Node, gethConfig) {
	// Load defaults.
	// 加载 默认配置
	cfg := gethConfig{
		// eth的默认配置
		Eth:       eth.DefaultConfig,
		// shh (whisper)的默认配置
		Shh:       whisper.DefaultConfig,
		// node的默认配置
		Node:      defaultNodeConfig(),
		// dashboard的默认配置
		Dashboard: dashboard.DefaultConfig,
	}

	// Load config file.
	// 加载全局的配置文件 (Name: "config")
	if file := ctx.GlobalString(configFileFlag.Name); file != "" {
		if err := loadConfig(file, &cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	}

	// Apply flags.
	// 将 ctx 中的内容设置到 cfg 中
	utils.SetNodeConfig(ctx, &cfg.Node)
	/**
	构建一个 不完整的 node 实例
	根据 cfg 去构建
	 */
	stack, err := node.New(&cfg.Node)
	if err != nil {
		utils.Fatalf("Failed to create the protocol stack: %v", err)
	}

	// 根据 命令行参数 及 node 实例 及 eth的cfg
	// 去设置相关的 eth cfg
	utils.SetEthConfig(ctx, stack, &cfg.Eth)
	// Name: "ethstats"
	if ctx.GlobalIsSet(utils.EthStatsURLFlag.Name) {
		cfg.Ethstats.URL = ctx.GlobalString(utils.EthStatsURLFlag.Name)
	}

	// 去设置相关的 shh cfg
	utils.SetShhConfig(ctx, stack, &cfg.Shh)
	// 去设置相关的 dashboard cfg
	utils.SetDashboardConfig(ctx, &cfg.Dashboard)

	/** 把初步创建好的不完整 node 和 相关 cfg 返回 */
	return stack, cfg
}

// enableWhisper returns true in case one of the whisper flags is set.
func enableWhisper(ctx *cli.Context) bool {
	for _, flag := range whisperFlags {
		if ctx.GlobalIsSet(flag.GetName()) {
			return true
		}
	}
	return false
}

/**
 创建一个Ethereum 节点实例
 */
func makeFullNode(ctx *cli.Context) *node.Node {

	// 先创建一个 不完整的 node 实例，及 构建geth的配置
	stack, cfg := makeConfigNode(ctx)

	/** 往 node 实例注册 ETH 服务 */
	utils.RegisterEthService(stack, &cfg.Eth)

	// 是否命令行配置了 dashboard
	if ctx.GlobalBool(utils.DashboardEnabledFlag.Name) {
		/** 往 node 注册 dashboard 服务 */
		utils.RegisterDashboardService(stack, &cfg.Dashboard, gitCommit)
	}
	// Whisper must be explicitly enabled by specifying at least 1 whisper flag or in dev mode
	// 必须通过指定至少1个 whisper 标记或 开发模式明确启用 whisper

	// 标识位： whisper 是否启用 (读取命令行参数)
	shhEnabled := enableWhisper(ctx)
	// Name: "shh" && Name: "dev"
	shhAutoEnabled := !ctx.GlobalIsSet(utils.WhisperEnabledFlag.Name) && ctx.GlobalIsSet(utils.DeveloperFlag.Name)
	if shhEnabled || shhAutoEnabled {
		// Name: "shh.maxmessagesize"
		if ctx.GlobalIsSet(utils.WhisperMaxMessageSizeFlag.Name) {
			cfg.Shh.MaxMessageSize = uint32(ctx.Int(utils.WhisperMaxMessageSizeFlag.Name))
		}
		// Name: "shh.pow"
		if ctx.GlobalIsSet(utils.WhisperMinPOWFlag.Name) {
			cfg.Shh.MinimumAcceptedPOW = ctx.Float64(utils.WhisperMinPOWFlag.Name)
		}
		/** 往node注册 shh 服务 (whisper 相关)*/
		utils.RegisterShhService(stack, &cfg.Shh)
	}

	// Add the Ethereum Stats daemon if requested.
	// 如果需要，添加以太坊统计守护程序。
	if cfg.Ethstats.URL != "" {

		/** 往 node 注册 EthStats 服务 */
		utils.RegisterEthStatsService(stack, cfg.Ethstats.URL)
	}
	// 最后返回完整的 node 节点实例
	return stack
}

// dumpConfig is the dumpconfig command.
func dumpConfig(ctx *cli.Context) error {
	_, cfg := makeConfigNode(ctx)
	comment := ""

	if cfg.Eth.Genesis != nil {
		cfg.Eth.Genesis = nil
		comment += "# Note: this config doesn't contain the genesis block.\n\n"
	}

	out, err := tomlSettings.Marshal(&cfg)
	if err != nil {
		return err
	}
	io.WriteString(os.Stdout, comment)
	os.Stdout.Write(out)
	return nil
}
