// Copyright 2015 The github.com/go-ethereum-analysis Authors
// This file is part of the github.com/go-ethereum-analysis library.
//
// The github.com/go-ethereum-analysis library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The github.com/go-ethereum-analysis library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the github.com/go-ethereum-analysis library. If not, see <http://www.gnu.org/licenses/>.

// Package nat provides access to common network port mapping protocols.
package nat

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-ethereum-analysis/log"
	"github.com/jackpal/go-nat-pmp"   // pmp 实现的  NAT
)

/**
NAT:	网络地址转换		(Network Address Translation)

NAPT:	网络地址端口转换    (Network Address Port Translation)

todo 它们都是地址转换，NAPT 与 NAT 的区别在于 NAT 是一对一转换，NAPT 是多对一转换.

	通俗来说NAT是 一个内部地址 转换成一个外部地址进行通信的，
	而NAPT是 多个内部地址使用 同一地址不同端口 转换成外部地址进行通信的.

NAPT 发送数据的时候会在源地址和目标地址上加上端口号（比如源地址：192.168.1.2:1010，目标地址：200.1.1.2:1020），回来的数据也是一样

NAPT与NAT的区别在于: NAPT不仅转换IP包中的IP地址，还对IP包中TCP和UDP的Port进行转换。这使得多台私有网主机利用 1个NAT公共IP 就可以同时和 公共网进行通信  (官方说明)  todo （NAPT 多了对TCP和UDP的端口号的转换）

todo 说白了区别就是:
		NAT：一个全局IP (用来对外网的) 对应一个私有IP（即一台内网计算机）

		NAPT:一个全局IP + 不同的端口号 (用来对外网的) 对应多个私有IP（即多台内网计算机）


todo NAT
		NAT网关有2个网络端口，其中公共网络端口的IP地址是统一分配的公共IP，为202.204.65.2;
		私有网络端口的IP地址是保留地址，为192.168.1.1.
		私有网中的主机 192.168.1.2 向公共网中的主机166.111.80.200发送了1个IP包（Des=166.111.80.200,Src=192.168.1.2）.
		当IP包经过NAT网关时，NAT会将IP包的源IP转换为NAT的公共 IP并转发到公共网，此时IP包（Des=166.111.80.200，Src=202.204.65.2）中已经不含任何私有网IP的信息.
		由于IP 包的源IP已经被转换成NAT的公共IP，响应的IP包（Des=202.204.65.2,Src=166.111.80.200）将被发送到NAT.
		这时，NAT会将IP包的目的IP转换成私有网中主机的IP，然后将IP包（Des=192.168.1.2，Src=166.111.80.200）转 发到私有网.
		对于通信双方而言，这种地址的转换过程是完全透明的.

todo  NAPT
		私有网主机192.168.1.2要访问公共网中的 Http服务器166.111.80.200
		首先，要建立TCP连接，假设分配的TCP Port是1010，发送了1个IP包（Des=166.111.80.200:80,Src=192.168.1.2:1010）,
		当IP包经过NAT 网关时，NAT会将IP包的源IP转换为NAT的公共IP，同时将源Port转换为NAT【动态分配】的1个Port.然后，转发到公共网，
		此时IP包 （Des=166.111.80.200：80，Src=202.204.65.2:2010）已经不含任何私有网IP和Port的信息.
		由于IP包的源 IP和Port已经被转换成NAT的公共IP和Port，响应的IP包 （Des=202.204.65.2:,Src=2010166.111.80.200:80）将被发送到NAT.
		这时NAT会将IP包的目的IP转换成 私有网主机的IP，同时将目的Port转换为私有网主机的Port，然后将IP包 （Des=192.168.1.2:1010，Src=166.111.80.200:80）转发到私网.
		对于通信双方而言，这种IP地址和Port的转 换是完全透明的.




 NAPT 是一种较流行的NAT的变体通过转换TCP或UDP协议端口号以及地址来提供并发性。除了一对源和目的IP地址以外，
		这个表还包括一对源和目的协议端口号，以及NAT盒使用的一个协议端口号.

 NAPT 的主要优势在于，能够使用一个全球有效IP地址获得通用性. 主要缺点在于其通信仅限于TCP 或 UDP.
		只要所有通信都采用TCP或UDP，NAPT就允许一台内部计算机访问多台外部计算机，
		并允许多台内部主机访问同一台外部计算机，相互之间不会发生冲突.
*/

//  NAPT 是内部机器通过路由器也就是网关向外部发送网络请求时，路由器记住内部机器的ip和端口，同时跟真正发送数据的外网端口绑定，产生一个临时映射表，
// 		 当收到外网数据以后通过这个映射表将数据转发给内部机器.
//
//  NAPT 是路由器肯定带的功能，其产生的nat映射表有多种类型，但都有时效，
// 		 也就是超过一段时间原来的nat映射就无效，然后新建新的nat映射.
// 	 	 nat映射必须先由 内部机器 向 外部网络 发起请求才会产生.

//	upnp 和 nat-pmp 差不多，就是在 路由器 和 内部机器 提供一个 中间服务 ，内部机器请求 upnp 将其使用到的端口跟某个外网端口绑定，
// 		 这样当 路由器 收到 外网请求 时先去upnp里查找是否此外网端口已经被upnp映射，如果被映射则将数据转发到内部机器对应的端口.
//
//  upnp  是把映射关系长期保存下来，外部机器可以主动向内部机器请求网络连接.
// 		  所以首先要路由器开启upnp功能 (一般由用户去路由器设置里手动开启upnp)，
// 		  然后 内部机器 的 程序 要 自己实现 upnp客户端功能：
// 			1、主动查找upnp服务
// 			2、主动增加映射
// 			3、删除映射 等
//
//	 upnp  UPnP (Universal Plug and Play) 是一种通用即 插即用协议， 用于简化网络设备的发现/控制过程，并且仅用于本地网络.
//			UPNP是基于NAPT工作的，确切地说UPNP是实现NAPT的一种方式，还有其他的办法也可以实现NAPT.


// nat-pmp  (NAT Port Mapping Protocol，缩写NAT-PMP) apple的协议，允许 私有网络里面的设备和路由沟通，以便外部的设备能和它联系，基于 UDP 协议. 可以理解成常见的 UPNP 的另外一个方式.


// todo 以太坊只做了upnpt和nat-pmp的端口映射,而且实现是调用了第三方开源库，但是没有做 NAPT udp 打洞.

// An implementation of nat.Interface can map local ports to ports
// accessible from the Internet.
type Interface interface {
	// These methods manage a mapping between a port on the local
	// machine to a port that can be connected to from the internet.
	//
	// protocol is "UDP" or "TCP". Some implementations allow setting
	// a display name for the mapping. The mapping may be removed by
	// the gateway when its lifetime ends.
	AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) error
	DeleteMapping(protocol string, extport, intport int) error

	// This method should return the external (Internet-facing)
	// address of the gateway device.
	ExternalIP() (net.IP, error)

	// Should return name of the method. This is used for logging.
	String() string
}

// Parse parses a NAT interface description.
// The following formats are currently accepted.
// Note that mechanism names are not case-sensitive.
//
//     "" or "none"         return nil
//     "extip:77.12.33.4"   will assume the local machine is reachable on the given IP
//     "any"                uses the first auto-detected mechanism
//     "upnp"               uses the Universal Plug and Play protocol
//     "pmp"                uses NAT-PMP with an auto-detected gateway address
//     "pmp:192.168.0.1"    uses NAT-PMP with the given gateway address
func Parse(spec string) (Interface, error) {
	var (
		parts = strings.SplitN(spec, ":", 2)
		mech  = strings.ToLower(parts[0])
		ip    net.IP
	)
	if len(parts) > 1 {
		ip = net.ParseIP(parts[1])
		if ip == nil {
			return nil, errors.New("invalid IP address")
		}
	}
	switch mech {
	case "", "none", "off":
		return nil, nil
	case "any", "auto", "on":
		return Any(), nil
	case "extip", "ip":
		if ip == nil {
			return nil, errors.New("missing IP address")
		}
		return ExtIP(ip), nil
	case "upnp":
		return UPnP(), nil
	case "pmp", "natpmp", "nat-pmp":
		return PMP(ip), nil
	default:
		return nil, fmt.Errorf("unknown mechanism %q", parts[0])
	}
}

const (
	mapTimeout        = 20 * time.Minute
	mapUpdateInterval = 15 * time.Minute
)

// Map adds a port mapping on m and keeps it alive until c is closed.
// This function is typically invoked in its own goroutine.
//
// `Map()` 在 m上添加了 端口映射，并保持活动状态，直到关闭 c
//
// 此函数通常在其自己的goroutine中调用
func Map(m Interface, c chan struct{}, protocol string, extport, intport int, name string) {
	log := log.New("proto", protocol, "extport", extport, "intport", intport, "interface", m)
	refresh := time.NewTimer(mapUpdateInterval)   // 下个 15 分钟刷新一次
	defer func() {
		refresh.Stop()
		log.Debug("Deleting port mapping")
		m.DeleteMapping(protocol, extport, intport)
	}()

	// 网 NAT 映射表实现 m 中添加, extport 和 intport 的 内外网端口映射  20分钟失效
	if err := m.AddMapping(protocol, extport, intport, name, mapTimeout); err != nil {
		log.Debug("Couldn't add port mapping", "err", err)
	} else {
		log.Info("Mapped network port")
	}
	for {
		select {
		case _, ok := <-c:
			if !ok {
				return
			}
		case <-refresh.C:
			log.Trace("Refreshing port mapping")
			// 刷新 NAT 端口映射表   20分钟失效
			if err := m.AddMapping(protocol, extport, intport, name, mapTimeout); err != nil {
				log.Debug("Couldn't add port mapping", "err", err)
			}
			refresh.Reset(mapUpdateInterval)  // 重置成 下个 15 分钟刷新一次
		}
	}
}

// ExtIP assumes that the local machine is reachable on the given
// external IP address, and that any required ports were mapped manually.
// Mapping operations will not return an error but won't actually do anything.
func ExtIP(ip net.IP) Interface {
	if ip == nil {
		panic("IP must not be nil")
	}
	return extIP(ip)
}

type extIP net.IP

func (n extIP) ExternalIP() (net.IP, error) { return net.IP(n), nil }
func (n extIP) String() string              { return fmt.Sprintf("ExtIP(%v)", net.IP(n)) }

// These do nothing.
func (extIP) AddMapping(string, int, int, string, time.Duration) error { return nil }
func (extIP) DeleteMapping(string, int, int) error                     { return nil }

// Any returns a port mapper that tries to discover any supported
// mechanism on the local network.
/**
todo 使用了兼容两个第三方库的实现 UPnP 和 PMP
 */
func Any() Interface {
	// TODO: attempt to discover whether the local machine has an
	// Internet-class address. Return ExtIP in this case.
	return startautodisc("UPnP or NAT-PMP", func() Interface {
		found := make(chan Interface, 2)
		go func() { found <- discoverUPnP() }()			// 监控 UPnP的
		go func() { found <- discoverPMP() }()			// 监控 NAT-PMP的

		for i := 0; i < cap(found); i++ {
			if c := <-found; c != nil {
				return c   // 一般来说, UPnP 和 NAT-PMP 只会由于一个 有信号回来
			}
		}
		return nil
	})
}

// UPnP returns a port mapper that uses UPnP. It will attempt to
// discover the address of your router using UDP broadcasts.
func UPnP() Interface {
	return startautodisc("UPnP", discoverUPnP)
}

// PMP returns a port mapper that uses NAT-PMP. The provided gateway
// address should be the IP of your router. If the given gateway
// address is nil, PMP will attempt to auto-discover the router.
func PMP(gateway net.IP) Interface {
	if gateway != nil {
		return &pmp{gw: gateway, c: natpmp.NewClient(gateway)}
	}
	return startautodisc("NAT-PMP", discoverPMP)
}

// autodisc represents a port mapping mechanism that is still being
// auto-discovered. Calls to the Interface methods on this type will
// wait until the discovery is done and then call the method on the
// discovered mechanism.
//
// This type is useful because discovery can take a while but we
// want return an Interface value from UPnP, PMP and Auto immediately.
type autodisc struct {
	what string // type of interface being autodiscovered
	once sync.Once
	doit func() Interface

	mu    sync.Mutex
	found Interface
}

func startautodisc(what string, doit func() Interface) Interface {
	// TODO: monitor network configuration and rerun doit when it changes.
	return &autodisc{what: what, doit: doit}
}

func (n *autodisc) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) error {
	if err := n.wait(); err != nil {
		return err
	}
	return n.found.AddMapping(protocol, extport, intport, name, lifetime)
}

func (n *autodisc) DeleteMapping(protocol string, extport, intport int) error {
	if err := n.wait(); err != nil {
		return err
	}
	return n.found.DeleteMapping(protocol, extport, intport)
}

func (n *autodisc) ExternalIP() (net.IP, error) {
	if err := n.wait(); err != nil {
		return nil, err
	}
	return n.found.ExternalIP()
}

func (n *autodisc) String() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.found == nil {
		return n.what
	} else {
		return n.found.String()
	}
}

// wait blocks until auto-discovery has been performed.
func (n *autodisc) wait() error {
	n.once.Do(func() {
		n.mu.Lock()
		n.found = n.doit()
		n.mu.Unlock()
	})
	if n.found == nil {
		return fmt.Errorf("no %s router discovered", n.what)
	}
	return nil
}
