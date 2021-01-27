// Copyright 2015 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

package p2p

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/crypto"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/crypto/ecies"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/crypto/secp256k1"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/crypto/sha3"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/p2p/discover"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/rlp"
	"github.com/golang/snappy"
)

// todo RLPx 传输协议原理:
//
// RLPx使用了  完全前向保密技术（perfect forward secrecy），通信双方生成随机公私钥对，交换各自的公钥，
// 		使用  自己的随机私钥  和  对方的公钥 生成共享秘密（shared-secret）.
// 		后续使用这个 共享秘密对称加密 传输的数据，即使一方的私钥被泄露，过去的通信还是安全的.

// todo 完全前向保密:
//
// 完全前向保密（perfect forward secrecy）技术是一种 秘钥协商协议，保证即使  服务器的私钥  被泄露， 会话秘钥 也不会被泄露.
// 			前向保密保护过去的会话抵抗秘钥或密码在未来泄露的威胁。为每一次会话产生唯一的会话秘钥，一个会话秘钥的泄露不会影响其它会话中传输的数据安全性。
//
//

// RLPx使用的加密系统：
//
// 		1、椭圆曲线secp256k1 基点G
//
// 		2、KDF(secretKey, len)：	密钥推导函数 NIST SP 800-56 Concatenation
//
// 		3、MAC(secretKey, m)：		HMAC函数，使用了SHA-256哈希
//
// 		4、AES(secretKey, iv, m)：	AES-128对称加密函数，CTR模式

// ECDH :Elliptic Curve Diffie-Hellman 椭圆曲线 Diffie-Hellman 秘钥交换协议
//
// ECDHE:（Ephemeral Elliptic Curve Diffie-Hellman）临时椭圆曲线 Diffie-Hellman 秘钥交换协议。
//
// ECIES加密
//		ECIES（Elliptic Curve Integrated Encryption Scheme，椭圆曲线综合加密方案） 作为 非对称秘钥 用于RLPx协议握手。
//
//

// RLPx 传输中的 加解密过程:
//
// 　Alice节点 想发送一份只有 Bob节点 能通过静态私钥 SK_b 解密的加密消息，需要 事先知道 Bob节点 的公钥 PK_b. 基本流程为：
//
//	 todo 发送端 处理, 对应函数 `initiatorEncHandshake()` 的流程：
//
//	　　1.为了加密消息 m，Alice 生成随机数 r <函数中的 nonce>， 通过 secp256k1 生成 元G <基点>， 得到对应的椭圆曲线公钥 R = r * G <临时的公私钥对中的 公钥>.
//
//	　　2. Alice节点 计算共享秘密 S = P_x，其中 P_x 为椭圆曲线上的点，且满足 (P_x, P_y) = r * PK_b
//
//	　　3. 推导 出 【加密使用的秘钥 SK_e 】和 【认证秘钥 SK_m 】, 其中满足  SK_e || SK_m = KDF(S, 32) = KDF(P_x, 32), 以及随机初始化向量 iv
//
//	　　4. Alice节点 发送 【加密消息 R|| iv || c || d 】 给Bob节点,其中:  c = AES(SK_e, iv, m),   而 d = MAC(keccak256(SK_m), iv || c)
//
//
//
//
//	 todo 接收端 处理, 对应函数 `receiverEncHandshake()` 的流程:
//
//	　　5. Bob节点 收到 【加密消息 R|| iv || c || d 】, 导出共享秘钥 S <也就是 P_x>,
// 				其中  (P_x, P_y) = r * PK_b = r * (G * SK_b) = SK_b * (r * G) = SK_b * R ,
// 				以及 加密秘钥 SK_e 和 认证秘钥 SK_m，  其中  SK_e || SK_m = KDF(S, 32) = KDF(P_x, 32)
//
//	　　6. Bob节点 验证认证消息，其中  d = MAC(keccak256(SK_m), iv || c)， 解密原始信息，其中 m = AES(SK_e, iv || c)



// todo 数据分帧
//
//	握手成功之后，在此连接上发送的所有业务信息，都通过连接协商秘密 (connection secrets) 按一定格式进行数据分帧.
//	握手后所有的消息都按帧 (frame) 传输. 一帧数据携带属于某一功能的一条加密消息.
//
// todo  初始握手后的所有消息均与“功能”相关. 而每个 RLPx 握手(连接) 上就可以同时使用 任何数量的功能 (如:  tx、block、header 等等).
//
//	目的:
//		分帧传输 的主要目的是在 单一连接上实现可靠的支持 多路复用协议.
// 		其次，因数据包分帧，为  消息认证码  产生了适当的分界点，使得加密流变得简单了.
// 		通过握手生成的密钥 对 数据帧 进行加密和验证.
//
//	格式:
//		帧头提供关于消息大小和消息源功能的信息。填充字节用于防止缓存区不足，使得帧组件按指定区块字节大小对齐.
//
//
// 			frame = header || header-mac || frame-data || frame-mac
//
// 			header = frame-size || header-data || padding


const (
	maxUint24 = ^uint32(0) >> 8

	sskLen = 16 // ecies.MaxSharedKeyLength(pubKey) / 2
	sigLen = 65 // elliptic S256
	pubLen = 64 // 512 bit pubkey in uncompressed representation without format byte
	shaLen = 32 // hash length (for nonce etc)

	authMsgLen  = sigLen + shaLen + pubLen + shaLen + 1
	authRespLen = pubLen + shaLen + 1

	eciesOverhead = 65 /* pubkey */ + 16 /* IV */ + 32 /* MAC */

	encAuthMsgLen  = authMsgLen + eciesOverhead  // size of encrypted pre-EIP-8 initiator handshake
	encAuthRespLen = authRespLen + eciesOverhead // size of encrypted pre-EIP-8 handshake reply

	// total timeout for encryption handshake and protocol
	// handshake in both directions.
	handshakeTimeout = 5 * time.Second

	// This is the timeout for sending the disconnect reason.
	// This is shorter than the usual timeout because we don't want
	// to wait if the connection is known to be bad anyway.
	discWriteTimeout = 1 * time.Second
)

// errPlainMessageTooLarge is returned if a decompressed message length exceeds
// the allowed 24 bits (i.e. length >= 16MB).
var errPlainMessageTooLarge = errors.New("message length >= 16MB")

// rlpx is the transport protocol used by actual (non-test) connections.
// It wraps the frame encoder with locks and read/write deadlines.
type rlpx struct {
	fd net.Conn

	rmu, wmu sync.Mutex
	rw       *rlpxFrameRW
}

func newRLPX(fd net.Conn) transport {
	fd.SetDeadline(time.Now().Add(handshakeTimeout))
	return &rlpx{fd: fd}
}

func (t *rlpx) ReadMsg() (Msg, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	t.fd.SetReadDeadline(time.Now().Add(frameReadTimeout))
	return t.rw.ReadMsg()
}

func (t *rlpx) WriteMsg(msg Msg) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	t.fd.SetWriteDeadline(time.Now().Add(frameWriteTimeout))
	return t.rw.WriteMsg(msg)
}

func (t *rlpx) close(err error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	// Tell the remote end why we're disconnecting if possible.
	if t.rw != nil {
		if r, ok := err.(DiscReason); ok && r != DiscNetworkError {
			// rlpx tries to send DiscReason to disconnected peer
			// if the connection is net.Pipe (in-memory simulation)
			// it hangs forever, since net.Pipe does not implement
			// a write deadline. Because of this only try to send
			// the disconnect reason message if there is no error.
			if err := t.fd.SetWriteDeadline(time.Now().Add(discWriteTimeout)); err == nil {
				SendItems(t.rw, discMsg, r)
			}
		}
	}
	t.fd.Close()
}

// 处理 RLPx 的协议握手
func (t *rlpx) doProtoHandshake(our *protoHandshake) (their *protoHandshake, err error) {


	// 协议握手 发送简单的握手信息，检查 对方的响应，判断 【加密握手】 是否起作用，同时判断对方是否支持 todo 【snappy 压缩】
	//		todo	握手成功则建立连接才算真正完成

	// Writing our handshake happens concurrently, we prefer
	// returning the handshake read error. If the remote side
	// disconnects us early with a valid reason, we should return it
	// as the error so it can be tracked elsewhere.
	//
	//
	// 写握手 是同时发生的，我们更喜欢返回握手读取错误.
	// 如果远端有正当的理由 使我们与我们早断开连接，我们应该将其作为错误返回，以便可以在其他地方进行跟踪
	werr := make(chan error, 1)
	go func() { werr <- Send(t.rw, handshakeMsg, our) }()  // 往对端 node 发起 一个 hello信号
	if their, err = readProtocolHandshake(t.rw, our); err != nil {  // 判断 握手消息 相应状态
		<-werr // make sure the write terminates too
		return nil, err
	}
	if err := <-werr; err != nil {
		return nil, fmt.Errorf("write error: %v", err)
	}
	// If the protocol version supports Snappy encoding, upgrade immediately  如果协议版本支持Snappy编码，请立即升级
	t.rw.snappy = their.Version >= snappyProtocolVersion  // 默认 当前p2p功能版本为第5版 (开启 snappy 压缩)

	return their, nil
}

// 判断 握手消息 相应状态
func readProtocolHandshake(rw MsgReader, our *protoHandshake) (*protoHandshake, error) {
	msg, err := rw.ReadMsg()
	if err != nil {
		return nil, err
	}
	if msg.Size > baseProtocolMaxMsgSize {
		return nil, fmt.Errorf("message too big")
	}
	if msg.Code == discMsg {  // p2p 连接已经断开

		// Disconnect before protocol handshake is valid according to the
		// spec and we send it ourself if the posthanshake checks fail.
		// We can't return the reason directly, though, because it is echoed
		// back otherwise. Wrap it in a string instead.
		//
		//
		// 根据规范，在协议握手有效之前断开连接，如果后期握手检查失败，我们将自行发送
		// 但是，我们无法直接返回原因，因为否则会被回显. 而是将其包装在字符串中
		var reason [1]DiscReason
		rlp.Decode(msg.Payload, &reason)
		return nil, reason[0]
	}
	if msg.Code != handshakeMsg {  // 没有握手成功
		return nil, fmt.Errorf("expected handshake, got %x", msg.Code)
	}
	var hs protoHandshake
	if err := msg.Decode(&hs); err != nil {
		return nil, err
	}
	if (hs.ID == discover.NodeID{}) {
		return nil, DiscInvalidIdentity
	}
	return &hs, nil
}

// doEncHandshake runs the protocol handshake using authenticated
// messages. the protocol handshake is the first authenticated message
// and also verifies whether the encryption handshake 'worked' and the
// remote side actually provided the right public key.
//
//
// `doEncHandshake()` 使用  `已验证的消息运行协议`  握手.
// 			协议握手是第一个经过身份验证的消息，还可以验证加密握手是否“有效”并且远程端是否实际提供了正确的公钥
//
//  prv
func (t *rlpx) doEncHandshake(prv *ecdsa.PrivateKey, dial *discover.Node) (discover.NodeID, error) {
	var (
		sec secrets
		err error
	)

	// todo 加密握手 中 使用 密钥交换 算法
	// 			迪菲－赫尔曼（ECDH）算法是个重要加密学技术，可以用 当前node私钥 和 对方node公钥 计算出一个共享的密钥，
	// 						比如有 A、B 两个公私钥对，    ECDH(A私钥, B公钥) == ECDH(B私钥, A公钥).   是交换密钥的重点原理
	//
	//			以上 A私钥、A公钥 和 B私钥、B公钥 在这里 我们都是 临时秘钥对 (非 node 的密钥对)
	//


	// 当前 node 作为 服务端， 被 对端 node 连接进来时
	if dial == nil {
		sec, err = receiverEncHandshake(t.fd, prv)				// rlpx 传输协议的 接收端 (recipient, 接受连接的节点)

	// 当前 node 作为 客户端, 去连接 对端 node 时
	} else {
		sec, err = initiatorEncHandshake(t.fd, prv, dial.ID)	// rlpx 传输协议的 发送端 (initiator, 发起TCP连接请求的节点)
	}
	// sec 为 RLPx 传输的 共享秘钥信息

	// 计算共享秘密(shared secret)
	//  发起者和接受者在握手完成之后，通过  [认证消息authPacket]  和  [认证响应消息authRespPacket] 计算协商的连接秘密.
	//
	// 该连接秘密只有在当前连接中有效，所以当一方的 node 私钥被泄露之后，之前的通信消息还是安全的.


	if err != nil {
		return discover.NodeID{}, err
	}
	t.wmu.Lock()
	t.rw = newRLPXFrameRW(t.fd, sec)  // 给 conn  设置 共享秘钥,  后续 传输都用 共享秘钥中的 (加密秘钥  和 认证秘钥  处理消息)
	t.wmu.Unlock()
	return sec.RemoteID, nil
}

// encHandshake contains the state of the encryption handshake.
type encHandshake struct {
	initiator bool
	remoteID  discover.NodeID

	remotePub            *ecies.PublicKey  // remote-pubk    远端 publicKey 相关信息

	// initNonce: 随机的  发送者 nonce
	// respNonce:
	initNonce, respNonce []byte            // nonce    todo (这两 【发送方】 和 【接收方】 双方都持有 这两个 nonce, 并且表明的 init 和 resp 是一致的 ...)
	randomPrivKey        *ecies.PrivateKey // ecdhe-random   		自己 生成 随机临时私钥 (私钥是包含公钥的哦)
	remoteRandomPub      *ecies.PublicKey  // ecdhe-random-pubk  	对端 的 随机临时公钥
}

// secrets represents the connection secrets
// which are negotiated during the encryption handshake.
//
// todo 将 对方公钥remote-pubk,  aes-secret, mac-secret, egress-mac, ingress-mac 作为当前连接的【协商秘密（connection secrets） 】用于 数据分帧.
//
type secrets struct {
	RemoteID              discover.NodeID   // 公钥remote-pubk  (NodeId = 公钥X坐标值 + 公钥Y坐标值)
	AES, MAC              []byte			// 加密秘钥  和 认证秘钥
	EgressMAC, IngressMAC hash.Hash			// 出口连接消息认证码  和 入口连接消息认证码
	Token                 []byte  // 目前没用
}

// RLPx v4 handshake auth (defined in EIP-8).
//
// RLPx v4 握手身份验证 (在 EIP-8 中定义)
type authMsgV4 struct {
	gotPlain bool // whether read packet had plain format.  读取的数据包是否具有纯格式

	Signature       [sigLen]byte		// 签名信息
	InitiatorPubkey [pubLen]byte		// 发送方的  节点nodeId  64byte
	Nonce           [shaLen]byte		// 发送方随机生成的 nonce, 用来做上面的 sign
	Version         uint				// 版本号, 目前全部默认为 4

	// Ignore additional fields (forward-compatibility)  忽略其他字段（正向兼容性）
	Rest []rlp.RawValue `rlp:"tail"`
}

// RLPx v4 handshake response (defined in EIP-8).
type authRespV4 struct {
	RandomPubkey [pubLen]byte
	Nonce        [shaLen]byte
	Version      uint

	// Ignore additional fields (forward-compatibility)
	Rest []rlp.RawValue `rlp:"tail"`
}

// secrets is called after the handshake is completed.
// It extracts the connection secrets from the handshake values.
//
// todo 返回  RLPx 传输用的  共享秘钥
//
// secrets() 是在 RLPx 握手完成后调用
//
// 从握手值 中提取 连接 的共享秘钥 (加密秘钥 SK_e  和 认证秘钥 SK_m)
func (h *encHandshake) secrets(auth, authResp []byte) (secrets, error) {  // 入参中包含的是  【发送方】 和 【接收方】有关 临时公钥的信息  (本地使用自己的 临时私钥 + 对端的 临时公钥 = 公共秘密)
	ecdheSecret, err := h.randomPrivKey.GenerateShared(h.remoteRandomPub, sskLen, sskLen)  // S = P_x, 其中 (P_x, P_y) = r * PK_b =  (自己的 私钥 * 别人的公钥 )
	if err != nil {
		return secrets{}, err
	}

	// 【加密消息 R|| iv || c || d 】 给Bob节点,其中:  c = AES(SK_e, iv, m),   而 d = MAC(keccak256(SK_m), iv || c)

	// derive base secrets from ephemeral key agreement
	sharedSecret := crypto.Keccak256(ecdheSecret, crypto.Keccak256(h.respNonce, h.initNonce))  	// todo 计算共享秘密  (使用上 双方的 nonce)
	aesSecret := crypto.Keccak256(ecdheSecret, sharedSecret)									// todo 计算AES秘密  (加密秘钥 SK_e)
	s := secrets{
		RemoteID: h.remoteID,
		AES:      aesSecret,		// 用于做加密
		MAC:      crypto.Keccak256(ecdheSecret, aesSecret),  									// todo 计算消息认证码秘密 (认证秘钥 SK_m)
	}

	// setup sha3 instances for the MACs
	mac1 := sha3.NewKeccak256()
	mac1.Write(xor(s.MAC, h.respNonce))
	mac1.Write(auth)

	mac2 := sha3.NewKeccak256()
	mac2.Write(xor(s.MAC, h.initNonce))
	mac2.Write(authResp)

	if h.initiator {
		s.EgressMAC, s.IngressMAC = mac1, mac2    	// 对发起方:  	计算出口连接消息认证码  和 计算入口连接消息认证码
	} else {
		s.EgressMAC, s.IngressMAC = mac2, mac1		// 对接收方:	计算出口连接消息认证码  和 计算入口连接消息认证码
	}

	// 将 对方公钥remote-pubk,  aes-secret, mac-secret, egress-mac, ingress-mac 作为当前连接的【协商秘密（connection secrets） 】用于 数据分帧.
	return s, nil
}

// staticSharedSecret returns the static shared secret, the result
// of key agreement between the local and remote static node key.
func (h *encHandshake) staticSharedSecret(prv *ecdsa.PrivateKey) ([]byte, error) { // 【发送方】和【接收方】的 共享秘密 的精髓就是: todo A私钥 + B公钥 = B私钥 + A公钥 = 共享秘密
	return ecies.ImportECDSA(prv).GenerateShared(h.remotePub, sskLen, sskLen)		// S = P_x, 其中 (P_x, P_y) = r * PK_b =  (自己的 私钥 * 别人的公钥 )
}

// initiatorEncHandshake negotiates a session token on conn.
// it should be called on the dialing side of the connection.
//
// prv is the local client's private key.
//
//	 todo 发送端 处理, 对应函数 `initiatorEncHandshake()` 的流程：
//
//	　　1.为了加密消息 m，Alice 生成随机数 r <函数中的 nonce>， 通过 secp256k1 生成 元G <基点>， 得到对应的椭圆曲线公钥 R = r * G <临时的公私钥对中的 公钥>.
//
//	　　2. Alice节点 计算共享秘密 S = P_x，其中 P_x 为椭圆曲线上的点，且满足 (P_x, P_y) = r * PK_b
//
//	　　3. 推导 出 【加密使用的秘钥 SK_e 】和 【认证秘钥 SK_m 】, 其中满足  SK_e || SK_m = KDF(S, 32) = KDF(P_x, 32), 以及随机初始化向量 iv
//
//	　　4. Alice节点 发送 【加密消息 R|| iv || c || d 】 给Bob节点,其中:  c = AES(SK_e, iv, m),   而 d = MAC(keccak256(SK_m), iv || c)
//
//
func initiatorEncHandshake(conn io.ReadWriter, prv *ecdsa.PrivateKey, remoteID discover.NodeID) (s secrets, err error) {

	//		在代码中是这样做的.
	//
	//		发起者的加密握手流程如下：
	//
	//			　　1.生成一个随机数 init-nonce todo (nonce 就是为了 签名相关的)
	//
	//			　　2.通过 `ecies` 生成随机秘钥对 ，随机私钥ephemeral-privk 与随机公钥ephemeral-pubk  todo (并没有使用 nonce 生成 临时密钥对哦)
	//
	//			　　3.用自己的私钥privk和对方的公钥remote_pubk 生成静态共享秘密static-shared-secrets
	//
	//			　　4.将生成的共享秘密 static-shared-secrets 与 随机数 init-nonce 进行异或运算，得到一个哈希值
	//
	//			　　5.使用自己的随机私钥ephemeral-privk 对该哈希值进行ECDSA签名计算，得到签名sig
	//
	//			　　6.将签名sig、自己的 node 公钥pubk 、初始nonce 作为 认证信息authMsg
	//
	//			　　7.对authMsg进行编码，然后再用对方的公钥remote_pubk进行ecies加密，得到认证数据包authPacket,将数据包通过发送给对方节点
	//
	//			　　8.等待读取对方节点的响应
	//
	//			　　9.收到对方响应之后，读取数据，使用自己的私钥privk 进行解密，再进行解码，得到认证响应authRespMsg
	//
	//			　　10.读取响应nonce, 和 对方的随机公钥remote-ephemeral-pubk

	h := &encHandshake{initiator: true, remoteID: remoteID}
	authMsg, err := h.makeAuthMsg(prv)  //  创建 rlpx 传输协议 发送方 发起握手的  msg
	if err != nil {
		return s, err
	}
	authPacket, err := sealEIP8(authMsg, h)  // 封装成一般的 数据格式 包
	if err != nil {
		return s, err
	}

	// 将 msg 写入 conn
	if _, err = conn.Write(authPacket); err != nil {
		return s, err
	}

	authRespMsg := new(authRespV4)
	authRespPacket, err := readHandshakeMsg(authRespMsg, encAuthRespLen, prv, conn)  // 处理 对端接收方 响应 回来的数据包
	if err != nil {
		return s, err
	}
	if err := h.handleAuthResp(authRespMsg); err != nil {
		return s, err
	}

	// 将 加密秘钥  和 认证秘钥 封装到 secret 结构中并返回.  todo 即返回 共享秘钥
	return h.secrets(authPacket, authRespPacket)
}

// makeAuthMsg creates the initiator handshake message.
//
//  创建 rlpx 传输协议 发送方 发起握手的  msg
//
// 加密步骤:
//
//
//	　　1.为了加密消息 m，Alice 生成随机数 r <函数中的 nonce>， 通过 secp256k1 生成 元G <基点>， 得到对应的椭圆曲线公钥 R = r * G <临时的公私钥对中的 公钥>.
//
//	　　2. Alice节点 计算共享秘密 S = P_x，其中 P_x 为椭圆曲线上的点，且满足 (P_x, P_y) = r * PK_b
//
//	　　3. 推导 出 【加密使用的秘钥 SK_e 】和 【认证秘钥 SK_m 】, 其中满足  SK_e || SK_m = KDF(S, 32) = KDF(P_x, 32), 以及随机初始化向量 iv
//
//	　　4. Alice节点 发送 【加密消息 R|| iv || c || d 】 给Bob节点,其中:  c = AES(SK_e, iv, m),   而 d = MAC(keccak256(SK_m), iv || c)
//
func (h *encHandshake) makeAuthMsg(prv *ecdsa.PrivateKey) (*authMsgV4, error) {

	rpub, err := h.remoteID.Pubkey()  // 从 nodeId 中解出 publicKey
	if err != nil {
		return nil, fmt.Errorf("bad remoteID: %v", err)
	}
	h.remotePub = ecies.ImportECDSAPublic(rpub)
	// Generate random initiator nonce.   生成 随机的  发送者 nonce
	h.initNonce = make([]byte, shaLen)
	if _, err := rand.Read(h.initNonce); err != nil {
		return nil, err
	}
	// Generate random keypair to for ECDH.     使用 ECDH 随机生成 keypair
	h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		return nil, err
	}

	// Sign known message: static-shared-secret ^ nonce
	//
	//  S = P_x, 其中 (P_x, P_y) = r * PK_b
	token, err := h.staticSharedSecret(prv)  // 【发送方生成 authMsg 时用】 里面有,  使用 当前 node 的 私钥 对 远端节点的公钥 做加密  (token 是加密后的值)
	if err != nil {
		return nil, err
	}
	signed := xor(token, h.initNonce)		// 使用   token ^ 随机生成的nonce  算出 Hash值
	signature, err := crypto.Sign(signed, h.randomPrivKey.ExportECDSA())	// 用自己的 临时私钥 和 Hash 算出 签名. todo (和 handleAuthMsg() 中解出 我们这里的公钥相呼应)
	if err != nil {
		return nil, err
	}

	// 组装  rlpx 的 发起者 信息
	msg := new(authMsgV4)
	copy(msg.Signature[:], signature)		// 签名
	copy(msg.InitiatorPubkey[:], crypto.FromECDSAPub(&prv.PublicKey)[1:]) // 节点的 nodeId
	copy(msg.Nonce[:], h.initNonce)		// 随机生成的 发送方 nonce 值
	msg.Version = 4

	return msg, nil
}

func (h *encHandshake) handleAuthResp(msg *authRespV4) (err error) {
	h.respNonce = msg.Nonce[:]
	h.remoteRandomPub, err = importPublicKey(msg.RandomPubkey[:])
	return err
}

// receiverEncHandshake negotiates a session token on conn.
// it should be called on the listening side of the connection.
//
// prv is the local client's private key.
//
//
//	 todo 接收端 处理, 对应函数 `receiverEncHandshake()` 的流程:
//
//	　　5. Bob节点 收到 【加密消息 R|| iv || c || d 】, 导出共享秘钥 S <也就是 P_x>,
// 				其中  (P_x, P_y) = r * PK_b = r * (G * SK_b) = SK_b * (r * G) = SK_b * R ,
// 				以及 加密秘钥 SK_e 和 认证秘钥 SK_m，  其中  SK_e || SK_m = KDF(S, 32) = KDF(P_x, 32)
//
//	　　6. Bob节点 验证认证消息，其中  d = MAC(keccak256(SK_m), iv || c)， 解密原始信息，其中 m = AES(SK_e, iv || c)
//
func receiverEncHandshake(conn io.ReadWriter, prv *ecdsa.PrivateKey) (s secrets, err error) {

	// 在代码中是这样做的.
	//
	// 	接受者加密握手流程：
	//
	//	　　1.接收方读取对方发送的加密握手数据包
	//
	//	　　2.先通过自己的私钥privk解密数据包，然后进行解码，得到认证数据authMsg
	//
	//	　　3.获取对方的remote_pubk， 和nonce
	//
	//	　　4.生成随机ECDH 秘钥对, 私钥ephemeral-privk 与公钥ephemeral-pubk
	//
	//	　　5.通过自己的私钥privk 和对方的公钥remote-pubk生成协商的静态共享秘密static-shared-secrets
	//
	//	　　6.用nonce对静态共享秘密进行异或运算得到 签名的消息signedMsg
	//
	//	　　7.用signedMsg 和authMsg中的签名信息，恢复出对方的随机公钥remote-ephemeral-pubk
	//
	//	　　8.生成随机数responseNonce, 与随机公钥ephemeral-pubk 作为认证响应authRespMsg
	//
	//	　　9.对authRespMsg进行编码， 然后用对方的公钥remote-pubk进行加密生成认证响应数据authresponsePacket
	//
	//	　　10.将authResponsePacket 发送给对方
	//


	authMsg := new(authMsgV4)
	authPacket, err := readHandshakeMsg(authMsg, encAuthMsgLen, prv, conn)  // 从 conn 中读取 接收到的 数据包
	if err != nil {
		return s, err
	}
	h := new(encHandshake)
	if err := h.handleAuthMsg(authMsg, prv); err != nil {  //  接收方 处理 rlpx 传输协议 发送方 发来握手的  msg
		return s, err
	}

	authRespMsg, err := h.makeAuthResp()  // 构造 RLPx 的 响应数据包
	if err != nil {
		return s, err
	}
	var authRespPacket []byte
	if authMsg.gotPlain {  // 读取的数据包 是否 具有纯格式
		authRespPacket, err = authRespMsg.sealPlain(h)  // 封装数据格式
	} else {
		authRespPacket, err = sealEIP8(authRespMsg, h)  // 一般的数据格式
	}
	if err != nil {
		return s, err
	}
	if _, err = conn.Write(authRespPacket); err != nil {  // 将 响应 写回  发送端
		return s, err
	}

	// 返回 RLPx 传输的 共享秘钥
	return h.secrets(authPacket, authRespPacket)
}

//  接收方 处理 rlpx 传输协议 发送方 发来握手的  msg
//
// 解密步骤:
//
//	 todo 接收端 处理, 对应函数 `receiverEncHandshake()` 的流程:
//
//	　　5. Bob节点 收到 【加密消息 R|| iv || c || d 】, 导出共享秘钥 S <也就是 P_x>,
// 				其中  (P_x, P_y) = r * PK_b = r * (G * SK_b) = SK_b * (r * G) = SK_b * R ,
// 				以及 加密秘钥 SK_e 和 认证秘钥 SK_m，  其中  SK_e || SK_m = KDF(S, 32) = KDF(P_x, 32)
//
//	　　6. Bob节点 验证认证消息，其中  d = MAC(keccak256(SK_m), iv || c)， 解密原始信息，其中 m = AES(SK_e, iv || c)
//
func (h *encHandshake) handleAuthMsg(msg *authMsgV4, prv *ecdsa.PrivateKey) error {
	// Import the remote identity.
	h.initNonce = msg.Nonce[:]			// 发送方声称的  nonce
	h.remoteID = msg.InitiatorPubkey	// 发送方的 nodeId
	rpub, err := h.remoteID.Pubkey()
	if err != nil {
		return fmt.Errorf("bad remoteID: %#v", err)
	}
	h.remotePub = ecies.ImportECDSAPublic(rpub)

	// Generate random keypair for ECDH.
	// If a private key is already set, use it instead of generating one (for testing).
	if h.randomPrivKey == nil {
		h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil)  // 测试代码
		if err != nil {
			return err
		}
	}

	// Check the signature.
	token, err := h.staticSharedSecret(prv) // 【接收方 处理 authMsg 时用】 里面有,  使用 当前 node 的 私钥 对 远端节点的公钥 做加密  (token 是加密后的值)
	if err != nil {
		return err
	}
	signedMsg := xor(token, h.initNonce)  // 使用   token ^ 随机生成的nonce  算出 Hash值
	remoteRandomPub, err := secp256k1.RecoverPubkey(signedMsg, msg.Signature[:])  // 使用 Hash 和 签名 解出 发送方的 临时随机PubKey  todo (和 makeAuthMsg() 中 使用他们自己的临时私钥算出签名 相呼应)
	if err != nil {
		return err
	}
	h.remoteRandomPub, _ = importPublicKey(remoteRandomPub)
	return nil
}


// 构造 RLPx 的 响应数据包
func (h *encHandshake) makeAuthResp() (msg *authRespV4, err error) {
	// Generate random nonce.
	h.respNonce = make([]byte, shaLen)
	if _, err = rand.Read(h.respNonce); err != nil {
		return nil, err
	}

	msg = new(authRespV4)
	copy(msg.Nonce[:], h.respNonce)
	copy(msg.RandomPubkey[:], exportPubkey(&h.randomPrivKey.PublicKey))   // 接收方自己生成的 随机nonce  和 临时公钥 相应回给 发送方 (发送方不需要推我们这边的 临时公钥了)
	msg.Version = 4
	return msg, nil
}

func (msg *authMsgV4) sealPlain(h *encHandshake) ([]byte, error) {
	buf := make([]byte, authMsgLen)
	n := copy(buf, msg.Signature[:])
	n += copy(buf[n:], crypto.Keccak256(exportPubkey(&h.randomPrivKey.PublicKey)))
	n += copy(buf[n:], msg.InitiatorPubkey[:])
	n += copy(buf[n:], msg.Nonce[:])
	buf[n] = 0 // token-flag
	return ecies.Encrypt(rand.Reader, h.remotePub, buf, nil, nil)
}

func (msg *authMsgV4) decodePlain(input []byte) {
	n := copy(msg.Signature[:], input)
	n += shaLen // skip sha3(initiator-ephemeral-pubk)
	n += copy(msg.InitiatorPubkey[:], input[n:])
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
	msg.gotPlain = true
}

// 封装数据格式
func (msg *authRespV4) sealPlain(hs *encHandshake) ([]byte, error) {
	buf := make([]byte, authRespLen)
	n := copy(buf, msg.RandomPubkey[:])
	copy(buf[n:], msg.Nonce[:])
	return ecies.Encrypt(rand.Reader, hs.remotePub, buf, nil, nil)
}

func (msg *authRespV4) decodePlain(input []byte) {
	n := copy(msg.RandomPubkey[:], input)
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
}

var padSpace = make([]byte, 300)

//
func sealEIP8(msg interface{}, h *encHandshake) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, msg); err != nil {
		return nil, err
	}
	// pad with random amount of data. the amount needs to be at least 100 bytes to make
	// the message distinguishable from pre-EIP-8 handshakes.
	pad := padSpace[:mrand.Intn(len(padSpace)-100)+100]
	buf.Write(pad)
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(buf.Len()+eciesOverhead))

	enc, err := ecies.Encrypt(rand.Reader, h.remotePub, buf.Bytes(), nil, prefix)
	return append(prefix, enc...), err
}

type plainDecoder interface {
	decodePlain([]byte)
}

func readHandshakeMsg(msg plainDecoder, plainSize int, prv *ecdsa.PrivateKey, r io.Reader) ([]byte, error) {
	buf := make([]byte, plainSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return buf, err
	}
	// Attempt decoding pre-EIP-8 "plain" format.
	key := ecies.ImportECDSA(prv)
	if dec, err := key.Decrypt(buf, nil, nil); err == nil {
		msg.decodePlain(dec)
		return buf, nil
	}
	// Could be EIP-8 format, try that.
	prefix := buf[:2]
	size := binary.BigEndian.Uint16(prefix)
	if size < uint16(plainSize) {
		return buf, fmt.Errorf("size underflow, need at least %d bytes", plainSize)
	}
	buf = append(buf, make([]byte, size-uint16(plainSize)+2)...)
	if _, err := io.ReadFull(r, buf[plainSize:]); err != nil {
		return buf, err
	}
	dec, err := key.Decrypt(buf[2:], nil, prefix)
	if err != nil {
		return buf, err
	}
	// Can't use rlp.DecodeBytes here because it rejects
	// trailing data (forward-compatibility).
	s := rlp.NewStream(bytes.NewReader(dec), 0)
	return buf, s.Decode(msg)
}

// importPublicKey unmarshals 512 bit public keys.
func importPublicKey(pubKey []byte) (*ecies.PublicKey, error) {
	var pubKey65 []byte
	switch len(pubKey) {
	case 64:
		// add 'uncompressed key' flag
		pubKey65 = append([]byte{0x04}, pubKey...)
	case 65:
		pubKey65 = pubKey
	default:
		return nil, fmt.Errorf("invalid public key length %v (expect 64/65)", len(pubKey))
	}
	// TODO: fewer pointless conversions
	pub, err := crypto.UnmarshalPubkey(pubKey65)
	if err != nil {
		return nil, err
	}
	return ecies.ImportECDSAPublic(pub), nil
}

func exportPubkey(pub *ecies.PublicKey) []byte {
	if pub == nil {
		panic("nil pubkey")
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)[1:]
}

func xor(one, other []byte) (xor []byte) {
	xor = make([]byte, len(one))
	for i := 0; i < len(one); i++ {
		xor[i] = one[i] ^ other[i]
	}
	return xor
}

var (
	// this is used in place of actual frame header data.
	// TODO: replace this when Msg contains the protocol type code.
	zeroHeader = []byte{0xC2, 0x80, 0x80}
	// sixteen zero bytes
	zero16 = make([]byte, 16)
)

// rlpxFrameRW implements a simplified version of RLPx framing.
// chunked messages are not supported and all headers are equal to
// zeroHeader.
//
// rlpxFrameRW is not safe for concurrent use from multiple goroutines.
//
type rlpxFrameRW struct {   // RLPx 协议的 数据帧 结构
	conn io.ReadWriter
	enc  cipher.Stream
	dec  cipher.Stream

	macCipher  cipher.Block

	// RLPx中的消息认证 (Message authentication) 使用了两个keccak256状态，分别用于两个传输方向。egress-mac和ingress-mac分别代表发送和接收状态
	egressMAC  hash.Hash   	// 发送状态 (每次发送都会变更)
	ingressMAC hash.Hash	// 接收状态 (每次接收都会变更)

	snappy bool		// 是否开启 snappy 压缩编码
}

func newRLPXFrameRW(conn io.ReadWriter, s secrets) *rlpxFrameRW {
	macc, err := aes.NewCipher(s.MAC)
	if err != nil {
		panic("invalid MAC secret: " + err.Error())
	}
	encc, err := aes.NewCipher(s.AES)
	if err != nil {
		panic("invalid AES secret: " + err.Error())
	}
	// we use an all-zeroes IV for AES because the key used
	// for encryption is ephemeral.
	iv := make([]byte, encc.BlockSize())
	return &rlpxFrameRW{
		conn:       conn,
		enc:        cipher.NewCTR(encc, iv),
		dec:        cipher.NewCTR(encc, iv),
		macCipher:  macc,
		egressMAC:  s.EgressMAC,
		ingressMAC: s.IngressMAC,
	}
}

// 将 消息 按照 RLPx 协议格式,  写入 conn
//
// 加密握手成功之后，在此连接上发送的所有业务信息，都通过连接协商秘密（connection secrets） 按一定格式进行数据分帧
//
func (rw *rlpxFrameRW) WriteMsg(msg Msg) error {

	// frame = header || header-mac || frame-data || frame-mac
	//
	// header = frame-size || header-data || padding

	ptype, _ := rlp.EncodeToBytes(msg.Code)

	// if snappy is enabled, compress message now
	//
	// 如果 开启了 snappy 数据压缩, 那么 我们需要将 待传输的 数据进行 压缩
	if rw.snappy {
		if msg.Size > maxUint24 {  // 16777215 byte
			return errPlainMessageTooLarge
		}
		payload, _ := ioutil.ReadAll(msg.Payload)
		payload = snappy.Encode(nil, payload)  // 将数据 做 snappy 压缩编码

		msg.Payload = bytes.NewReader(payload)
		msg.Size = uint32(len(payload))
	}
	// write header
	headbuf := make([]byte, 32)
	fsize := uint32(len(ptype)) + msg.Size
	if fsize > maxUint24 {
		return errors.New("message size overflows uint24")
	}
	putInt24(fsize, headbuf) // TODO: check overflow
	copy(headbuf[3:], zeroHeader)
	rw.enc.XORKeyStream(headbuf[:16], headbuf[:16]) // first half is now encrypted

	// write header MAC
	copy(headbuf[16:], updateMAC(rw.egressMAC, rw.macCipher, headbuf[:16]))
	if _, err := rw.conn.Write(headbuf); err != nil {
		return err
	}

	// write encrypted frame, updating the egress MAC hash with
	// the data written to conn.
	tee := cipher.StreamWriter{S: rw.enc, W: io.MultiWriter(rw.conn, rw.egressMAC)}
	if _, err := tee.Write(ptype); err != nil {
		return err
	}
	if _, err := io.Copy(tee, msg.Payload); err != nil {
		return err
	}
	if padding := fsize % 16; padding > 0 {
		if _, err := tee.Write(zero16[:16-padding]); err != nil {
			return err
		}
	}

	// write frame MAC. egress MAC hash is up to date because
	// frame content was written to it as well.
	fmacseed := rw.egressMAC.Sum(nil)
	mac := updateMAC(rw.egressMAC, rw.macCipher, fmacseed)
	_, err := rw.conn.Write(mac)
	return err
}

// 将按照 RLPx 协议格式的 消息,  从 conn 中读出来
//
// 加密握手成功之后，在此连接上发送的所有业务信息，都通过连接 协商秘密 (connection secrets) 按一定格式进行数据分帧
//
func (rw *rlpxFrameRW) ReadMsg() (msg Msg, err error) {


	// frame = header || header-mac || frame-data || frame-mac
	//
	// header = frame-size || header-data || padding


	// read the header
	headbuf := make([]byte, 32)
	if _, err := io.ReadFull(rw.conn, headbuf); err != nil {
		return msg, err
	}
	// verify header mac
	shouldMAC := updateMAC(rw.ingressMAC, rw.macCipher, headbuf[:16])
	if !hmac.Equal(shouldMAC, headbuf[16:]) {
		return msg, errors.New("bad header MAC")
	}
	rw.dec.XORKeyStream(headbuf[:16], headbuf[:16]) // first half is now decrypted
	fsize := readInt24(headbuf)
	// ignore protocol type for now

	// read the frame content
	var rsize = fsize // frame size rounded up to 16 byte boundary
	if padding := fsize % 16; padding > 0 {
		rsize += 16 - padding
	}
	framebuf := make([]byte, rsize)
	if _, err := io.ReadFull(rw.conn, framebuf); err != nil {
		return msg, err
	}

	// read and validate frame MAC. we can re-use headbuf for that.
	rw.ingressMAC.Write(framebuf)
	fmacseed := rw.ingressMAC.Sum(nil)
	if _, err := io.ReadFull(rw.conn, headbuf[:16]); err != nil {
		return msg, err
	}
	shouldMAC = updateMAC(rw.ingressMAC, rw.macCipher, fmacseed)
	if !hmac.Equal(shouldMAC, headbuf[:16]) {
		return msg, errors.New("bad frame MAC")
	}

	// decrypt frame content
	rw.dec.XORKeyStream(framebuf, framebuf)

	// decode message code
	content := bytes.NewReader(framebuf[:fsize])
	if err := rlp.Decode(content, &msg.Code); err != nil {
		return msg, err
	}
	msg.Size = uint32(content.Len())
	msg.Payload = content

	// if snappy is enabled, verify and decompress message
	//
	// 如果启用了snappy，请验证并解压缩消息
	if rw.snappy {
		payload, err := ioutil.ReadAll(msg.Payload)
		if err != nil {
			return msg, err
		}
		size, err := snappy.DecodedLen(payload)
		if err != nil {
			return msg, err
		}
		if size > int(maxUint24) {
			return msg, errPlainMessageTooLarge
		}
		payload, err = snappy.Decode(nil, payload)
		if err != nil {
			return msg, err
		}
		msg.Size, msg.Payload = uint32(size), bytes.NewReader(payload)
	}
	return msg, nil
}

// updateMAC reseeds the given hash with encrypted seed.
// it returns the first 16 bytes of the hash sum after seeding.
func updateMAC(mac hash.Hash, block cipher.Block, seed []byte) []byte {
	aesbuf := make([]byte, aes.BlockSize)
	block.Encrypt(aesbuf, mac.Sum(nil))
	for i := range aesbuf {
		aesbuf[i] ^= seed[i]
	}
	mac.Write(aesbuf)
	return mac.Sum(nil)[:16]
}

func readInt24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func putInt24(v uint32, b []byte) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}
