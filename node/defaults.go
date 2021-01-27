// Copyright 2016 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
// This file is part of the github.com/blockchain-analysis-study/go-ethereum-analysis library.
//
// The github.com/blockchain-analysis-study/go-ethereum-analysis library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The github.com/blockchain-analysis-study/go-ethereum-analysis library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the github.com/blockchain-analysis-study/go-ethereum-analysis library. If not, see <http://www.gnu.org/licenses/>.

package node

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/p2p"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/p2p/nat"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/rpc"
)

// 一些客户端 http 或者 ws 的默认配置项
const (
	DefaultHTTPHost = "localhost" // Default host interface for the HTTP RPC server
	DefaultHTTPPort = 8545        // Default TCP port for the HTTP RPC server
	DefaultWSHost   = "localhost" // Default host interface for the websocket RPC server
	DefaultWSPort   = 8546        // Default TCP port for the websocket RPC server
)

// DefaultConfig contains reasonable default settings.
var DefaultConfig = Config{
	DataDir:          DefaultDataDir(),
	HTTPPort:         DefaultHTTPPort,
	HTTPModules:      []string{"net", "web3"},
	HTTPVirtualHosts: []string{"localhost"},
	HTTPTimeouts:     rpc.DefaultHTTPTimeouts,
	WSPort:           DefaultWSPort,
	WSModules:        []string{"net", "web3"},

	/**
	默认的 p2p 选项
	 */
	P2P: p2p.Config{
		ListenAddr: ":30303",
		MaxPeers:   25, // 默认连接 25个对端 peer
		NAT:        nat.Any(),  // 使用的 nat 机制为: any (兼容了 UPnP 和 NAT-PMP 两种实现)
	},
}

// DefaultDataDir is the default data directory to use for the databases and other
// persistence requirements.
/**
构建默认的 数据目录
(存放 chaindata)
 */
func DefaultDataDir() string {
	// Try to place the data folder in the user's home dir
	home := homeDir()
	if home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Ethereum")
		} else if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming", "Ethereum")
		} else {
			return filepath.Join(home, ".ethereum")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	return ""
}

func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}
