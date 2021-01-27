// Copyright 2014 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
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

package types

import (
	"container/heap"
	"errors"
	"io"
	"math/big"
	"sync/atomic"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/common"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/common/hexutil"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/crypto"
	"github.com/blockchain-analysis-study/go-ethereum-analysis/rlp"
)

//go:generate gencodec -type txdata -field-override txdataMarshaling -out gen_tx_json.go

var (
	ErrInvalidSig = errors.New("invalid transaction v, r, s values")
)

type Transaction struct {
	data txdata
	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

type txdata struct {
	AccountNonce uint64          `json:"nonce"    gencodec:"required"`
	Price        *big.Int        `json:"gasPrice" gencodec:"required"`
	GasLimit     uint64          `json:"gas"      gencodec:"required"`
	Recipient    *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int        `json:"value"    gencodec:"required"`
	Payload      []byte          `json:"input"    gencodec:"required"`

	// Signature values
	//
	// 签名的值
	//
	//
	// v：QUANTITY-ECDSA恢复ID
	// r：DATA，32字节-ECDSA签名r
	// s：DATA，32字节-ECDSA签名s
	//
	//  TODO (这里我们会想到 discover.NodeId 的 64 byte， 是公钥的 X + Y)
	//
	// todo r,s,v 是交易签名后的值，它们可以被用来生成签名者的公钥.
	//
	// 		R，S 是ECDSA椭圆加密算法的输出值，  TODO (这里我们会想到 discover.NodeId 的 64 byte， 是公钥的 X + Y)
	// 		V 是用于恢复结果的ID
	//
	// 	todo 比特币RSV的作用描述也适用于以太坊，为了避免【重放攻击】，以太坊在EIP 155中做了更多的调整
	//
	// len(r + s + v ) == 65
	//
	// 对于 非EIP155 的 r s v 的值是下面的规则:
	//
	// sig[0, 32) 	=> 	r
	// sig[32, 65) =>	s
	// sig[64] + 27 == v
	//
	// 而 EIP155 的 r s v 的值是下面的 规则:
	//
	// sig[0, 32) 	=> 	r
	// sig[32, 65) =>	s
	// sig[64] + 35 + chainId * 2  => v (这样纸, 在不同的 chain 上的tx不可以互相重放 ...)
	//
	// todo EIP 155：重放攻击保护——防止了在一个以太坊链上的交易被重复广播到另外一条链.
	//
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	// This is only used when marshaling to JSON.
	Hash *common.Hash `json:"hash" rlp:"-"`
}

type txdataMarshaling struct {
	AccountNonce hexutil.Uint64
	Price        *hexutil.Big
	GasLimit     hexutil.Uint64
	Amount       *hexutil.Big
	Payload      hexutil.Bytes
	V            *hexutil.Big
	R            *hexutil.Big
	S            *hexutil.Big
}

func NewTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, &to, amount, gasLimit, gasPrice, data)
}

func NewContractCreation(nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, nil, amount, gasLimit, gasPrice, data)
}

func newTransaction(nonce uint64, to *common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	d := txdata{
		AccountNonce: nonce,
		Recipient:    to,
		Payload:      data,
		Amount:       new(big.Int),
		GasLimit:     gasLimit,
		Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	if amount != nil {
		d.Amount.Set(amount)
	}
	if gasPrice != nil {
		d.Price.Set(gasPrice)
	}

	return &Transaction{data: d}
}

// ChainId returns which chain id this transaction was signed for (if at all)
func (tx *Transaction) ChainId() *big.Int {
	return deriveChainId(tx.data.V)
}

// Protected returns whether the transaction is protected from replay protection.
func (tx *Transaction) Protected() bool {
	return isProtectedV(tx.data.V)
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28
	}
	// anything not 27 or 28 is considered protected
	return true
}

// EncodeRLP implements rlp.Encoder
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &tx.data)
}

// DecodeRLP implements rlp.Decoder
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	err := s.Decode(&tx.data)
	if err == nil {
		tx.size.Store(common.StorageSize(rlp.ListSize(size)))
	}

	return err
}

// MarshalJSON encodes the web3 RPC transaction format.
func (tx *Transaction) MarshalJSON() ([]byte, error) {
	hash := tx.Hash()
	data := tx.data
	data.Hash = &hash
	return data.MarshalJSON()
}

// UnmarshalJSON decodes the web3 RPC transaction format.
func (tx *Transaction) UnmarshalJSON(input []byte) error {
	var dec txdata
	if err := dec.UnmarshalJSON(input); err != nil {
		return err
	}
	var V byte
	if isProtectedV(dec.V) {
		chainID := deriveChainId(dec.V).Uint64()
		V = byte(dec.V.Uint64() - 35 - 2*chainID)
	} else {
		V = byte(dec.V.Uint64() - 27)
	}
	if !crypto.ValidateSignatureValues(V, dec.R, dec.S, false) {
		return ErrInvalidSig
	}
	*tx = Transaction{data: dec}
	return nil
}

func (tx *Transaction) Data() []byte       { return common.CopyBytes(tx.data.Payload) }
func (tx *Transaction) Gas() uint64        { return tx.data.GasLimit }
func (tx *Transaction) GasPrice() *big.Int { return new(big.Int).Set(tx.data.Price) }
func (tx *Transaction) Value() *big.Int    { return new(big.Int).Set(tx.data.Amount) }
func (tx *Transaction) Nonce() uint64      { return tx.data.AccountNonce }
func (tx *Transaction) CheckNonce() bool   { return true }

// To returns the recipient address of the transaction.
// It returns nil if the transaction is a contract creation.
func (tx *Transaction) To() *common.Address {
	if tx.data.Recipient == nil {
		return nil
	}
	to := *tx.data.Recipient
	return &to
}

// Hash hashes the RLP encoding of tx.
// It uniquely identifies the transaction.
func (tx *Transaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(tx)
	tx.hash.Store(v)
	return v
}

// Size returns the true RLP encoded storage size of the transaction, either by
// encoding and returning it, or returning a previsouly cached value.
func (tx *Transaction) Size() common.StorageSize {
	if size := tx.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, &tx.data)
	tx.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// AsMessage returns the transaction as a core.Message.
//
// AsMessage requires a signer to derive the sender.
//
// XXX Rename message to something less arbitrary?
func (tx *Transaction) AsMessage(s Signer) (Message, error) {
	msg := Message{
		// tx中携带的 nonce 用来evm中做校验用
		nonce:      tx.data.AccountNonce,
		// 当前tx的gasLimit
		gasLimit:   tx.data.GasLimit,
		// 当前tx的gasPrice
		gasPrice:   new(big.Int).Set(tx.data.Price),
		// 当前tx的 接受者
		to:         tx.data.Recipient,
		// 当前tx的value
		amount:     tx.data.Amount,
		// 当前tx的 data 字段(携带的数据)
		data:       tx.data.Payload,
		// 标识位，表示evm执行tx时，是否检查nonce
		checkNonce: true,
	}

	var err error
	// 从签名中恢复 当前tx的发起者
	msg.from, err = Sender(s, tx)
	return msg, err
}

// WithSignature returns a new transaction with the given signature.
// This signature needs to be formatted as described in the yellow paper (v+27).
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {


	// 只有 EIP155Signer 和 FrontierSigner  (HomesteadSigner 的 `SignatureValues()` 其实里面就是调用了一次 FrontierSigner 的 `SignatureValues()`)
	//
	// 区别:
	//		EIP155 其实也是先用了一次 : HomesteadSigner{}.SignatureValues(tx, sig), 然后 做了 V = big.NewInt(int64(sig[64] + 35)) 和 V.Add(V, s.chainIdMul)
	//
	// 具体来说是, 如下:
	//
	// 对于 非EIP155 的 r s v 的值是下面的规则:
	//
	// sig[0, 32) 	=> 	r
	// sig[32, 65) =>	s
	// sig[64] + 27 == v
	//
	// 而 EIP155 的 r s v 的值是下面的 规则:
	//
	// sig[0, 32) 	=> 	r
	// sig[32, 65) =>	s
	// sig[64] + 35 + chainId * 2  => v (这样纸, 在不同的 chain 上的tx不可以互相重放 ...)
	//
	// todo EIP 155：重放攻击保护——防止了在一个以太坊链上的交易被重复广播到另外一条链.

	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := &Transaction{data: tx.data}
	cpy.data.R, cpy.data.S, cpy.data.V = r, s, v  // 填充 tx  的 R S V   <R S V 三者合起来就是 签名值>
	return cpy, nil
}

// Cost returns amount + gasprice * gaslimit.
//
// Cost: tx.Value + tx.Gas*tx.GasPrice
func (tx *Transaction) Cost() *big.Int {
	total := new(big.Int).Mul(tx.data.Price, new(big.Int).SetUint64(tx.data.GasLimit))
	total.Add(total, tx.data.Amount)
	return total
}

func (tx *Transaction) RawSignatureValues() (*big.Int, *big.Int, *big.Int) {
	return tx.data.V, tx.data.R, tx.data.S
}

// Transactions is a Transaction slice type for basic sorting.
//
// todo Transactions 是用于 基本排序<根据nonce排序> 的 tx列表
type Transactions []*Transaction

// Len returns the length of s.
func (s Transactions) Len() int { return len(s) }

// Swap swaps the i'th and the j'th element in s.
func (s Transactions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// GetRlp implements Rlpable and returns the i'th element of s in rlp.
func (s Transactions) GetRlp(i int) []byte {
	enc, _ := rlp.EncodeToBytes(s[i])
	return enc
}

// TxDifference returns a new set which is the difference between a and b.
func TxDifference(a, b Transactions) Transactions {
	keep := make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, tx := range b {
		remove[tx.Hash()] = struct{}{}
	}

	for _, tx := range a {
		if _, ok := remove[tx.Hash()]; !ok {
			keep = append(keep, tx)
		}
	}

	return keep
}

// TxByNonce implements the sort interface to allow sorting a list of transactions
// by their nonces. This is usually only useful for sorting transactions from a
// single account, otherwise a nonce comparison doesn't make much sense.
type TxByNonce Transactions

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].data.AccountNonce < s[j].data.AccountNonce }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// TxByPrice implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type TxByPrice Transactions

func (s TxByPrice) Len() int           { return len(s) }
func (s TxByPrice) Less(i, j int) bool { return s[i].data.Price.Cmp(s[j].data.Price) > 0 }
func (s TxByPrice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (s *TxByPrice) Push(x interface{}) {
	*s = append(*s, x.(*Transaction))
}

func (s *TxByPrice) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[0 : n-1]
	return x
}

// TransactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
//
/**
todo 这个只有 worker  在用

todo TransactionsByPriceAndNonce表示
	 一组Txs，这些 tx 可以按 利润最大化的排序顺序返回交易，
	*** 同时支持删除不可执行账户的全部交易。***
 */
type TransactionsByPriceAndNonce struct {

	// 按帐户nonce排序的事务列表
	txs    map[common.Address]Transactions // Per account nonce-sorted list of transactions

	// 每个唯一帐户的下一笔交易（价格堆）<根据 gasPrice 排序>
	heads  TxByPrice                       // Next transaction for each unique account (price heap)

	// 交易集的签署人
	signer Signer                          // Signer for the set of transactions
}

// NewTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
/**
todo NewTransactionsByPriceAndNonce 函数

todo	创建一个tx集，可以以 nonce-honor <现时荣誉> 方式检索 gasPrice排序 的 tx 。
todo
todo	请注意，输入映射是拥有所有权的，因此如果在将其提供给构造函数之后，调用方将不再与之交互。
 */
func NewTransactionsByPriceAndNonce(signer Signer, txs map[common.Address]Transactions) *TransactionsByPriceAndNonce {
	// Initialize a price based heap with the head transactions
	// 初始化一个 根据 gasPrice 最为堆排的tx最小堆
	heads := make(TxByPrice, 0, len(txs))
	for from, accTxs := range txs {
		/** 将 每个账户的tx集中的 第一个tx收集起来，用于做最小堆排序 */
		heads = append(heads, accTxs[0])
		// Ensure the sender address is from the signer
		// 确保 form是当前tx的签名者
		acc, _ := Sender(signer, accTxs[0])
		// 移除掉当前 账户的 tx集 中的第一个 tx
		txs[acc] = accTxs[1:]
		/** todo 如果 当前账户的第一个 tx 解出来的from 及当前账户不相等，则为非法交易，直接删除 txs 中该账户相关的所有 tx集 */
		if from != acc {
			delete(txs, from)
		}
	}
	// 初始化 最小堆
	heap.Init(&heads)

	// Assemble and return the transaction set
	// 组装机返回一个 tx 集
	return &TransactionsByPriceAndNonce{
		txs:    txs,
		heads:  heads,

		// todo  一般是 worker
		signer: signer,
	}
}

// Peek returns the next transaction by price.
//
// Peek: 按价格 <从堆中> 返回下一个交易。
func (t *TransactionsByPriceAndNonce) Peek() *Transaction {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0]
}

// Shift replaces the current best head with the next one from the same account.
//
// todo Shift: 用同一帐户中的下一个tx 替换当前的 当前堆的头元素<tx>。
func (t *TransactionsByPriceAndNonce) Shift() {

	// todo 从当前 堆顶的 tx中解出当前tx对应的 账户
	acc, _ := Sender(t.signer, t.heads[0])

	// todo 获取当前账户的 在堆中的 所有 tx
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {

		// 使用 tx 列表中第一个 tx 替换堆顶， 并重新调整堆，
		// todo 注意： 上面为什么说是下一个 tx？ 因为当执行到这个 txs[0]的时候还是不满足，再次进入 `Shift()` 时，
		// 		拉出来的新列表是 txs[1:] 了，而新的 txs[0]，对于原先的 txs[0]来说就是下一个 tx 啊
		t.heads[0], t.txs[acc] = txs[0], txs[1:]

		// 调整堆
		heap.Fix(&t.heads, 0)
	} else {

		// todo 否则，如果该 tx 是该 账户的最后一个 tx 了，那么从堆中移除当前tx
		heap.Pop(&t.heads)
	}
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
//
// todo Pop: 移除最佳 tx，*不*  将其替换为同一帐户中的下一笔交易。 当无法执行 tx 时应使用此功能，因此所有后续交易应从同一帐户中丢弃。
func (t *TransactionsByPriceAndNonce) Pop() {
	// todo 从堆中移除当前 tx
	heap.Pop(&t.heads)
}

// Message is a fully derived transaction and implements core.Message
//
// NOTE: In a future PR this will be removed.
type Message struct {
	to         *common.Address
	from       common.Address
	nonce      uint64
	amount     *big.Int
	gasLimit   uint64
	gasPrice   *big.Int
	data       []byte
	checkNonce bool
}

func NewMessage(from common.Address, to *common.Address, nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, checkNonce bool) Message {
	return Message{
		from:       from,
		to:         to,
		nonce:      nonce,
		amount:     amount,
		gasLimit:   gasLimit,
		gasPrice:   gasPrice,
		data:       data,
		checkNonce: checkNonce,
	}
}

func (m Message) From() common.Address { return m.from }
func (m Message) To() *common.Address  { return m.to }
func (m Message) GasPrice() *big.Int   { return m.gasPrice }
func (m Message) Value() *big.Int      { return m.amount }
func (m Message) Gas() uint64          { return m.gasLimit }
func (m Message) Nonce() uint64        { return m.nonce }
func (m Message) Data() []byte         { return m.data }
func (m Message) CheckNonce() bool     { return m.checkNonce }
