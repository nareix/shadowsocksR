package shadowsocksr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"

	"github.com/nareix/shadowsocksR/tools"
)

var errEmptyPassword = errors.New("empty key")

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

func newCTRStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newAESCTRStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newCTRStream(block, err, key, iv, doe)
}

func newOFBStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func newAESOFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newOFBStream(block, err, key, iv, doe)
}

func newCFBStream(block cipher.Block, err error, key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	} else {
		return cipher.NewCFBDecrypter(block, iv), nil
	}
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newDESStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := des.NewCipher(key)
	return newCFBStream(block, err, key, iv, doe)
}

func newRC4MD5Stream(key, iv []byte, _ DecOrEnc) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}

type salsaStreamCipher struct {
	nonce   [8]byte
	key     [32]byte
	counter int
}

type cipherInfo struct {
	keyLen    int
	ivLen     int
	newStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var streamCipherMethod = map[string]*cipherInfo{
	"aes-128-cfb":      {16, 16, newAESCFBStream},
	"aes-192-cfb":      {24, 16, newAESCFBStream},
	"aes-256-cfb":      {32, 16, newAESCFBStream},
	"aes-128-ctr":      {16, 16, newAESCTRStream},
	"aes-192-ctr":      {24, 16, newAESCTRStream},
	"aes-256-ctr":      {32, 16, newAESCTRStream},
	"aes-128-ofb":      {16, 16, newAESOFBStream},
	"aes-192-ofb":      {24, 16, newAESOFBStream},
	"aes-256-ofb":      {32, 16, newAESOFBStream},
	"des-cfb":          {8, 8, newDESStream},
	"rc4-md5":          {16, 16, newRC4MD5Stream},
	"rc4-md5-6":        {16, 6, newRC4MD5Stream},
}

func CheckCipherMethod(method string) error {
	if method == "" {
		method = "rc4-md5"
	}
	_, ok := streamCipherMethod[method]
	if !ok {
		return errors.New("Unsupported encryption method: " + method)
	}
	return nil
}

type StreamCipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipherInfo
	iv   []byte
}

// NewStreamCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewStreamCipher(method, password string) (c *StreamCipher, err error) {
	if password == "" {
		return nil, errEmptyPassword
	}
	if method == "" {
		method = "rc4-md5"
	}
	mi, ok := streamCipherMethod[method]
	if !ok {
		return nil, errors.New("Unsupported encryption method: " + method)
	}

	key := tools.EVPBytesToKey(password, mi.keyLen)

	c = &StreamCipher{key: key, info: mi}

	if err != nil {
		return nil, err
	}
	return c, nil
}

// Initializes the block cipher with CFB mode, returns IV.
func (c *StreamCipher) initEncrypt() (iv []byte, err error) {
	if c.iv == nil {
		iv = make([]byte, c.info.ivLen)
		rand.Read(iv)
		c.iv = iv
	} else {
		iv = c.iv
	}
	c.enc, err = c.info.newStream(c.key, iv, Encrypt)
	return
}

func (c *StreamCipher) initDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.newStream(c.key, iv, Decrypt)
	return
}

func (c *StreamCipher) encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *StreamCipher) decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}

// Copy creates a new cipher at it's initial state.
func (c *StreamCipher) Copy() *StreamCipher {
	// This optimization maybe not necessary. But without this function, we
	// need to maintain a table cache for newTableCipher and use lock to
	// protect concurrent access to that cache.

	// AES and DES ciphers does not return specific types, so it's difficult
	// to create copy. But their initialization time is less than 4000ns on my
	// 2.26 GHz Intel Core 2 Duo processor. So no need to worry.

	// Currently, blow-fish and cast5 initialization cost is an order of
	// magnitude slower than other ciphers. (I'm not sure whether this is
	// because the current implementation is not highly optimized, or this is
	// the nature of the algorithm.)

	nc := *c
	nc.enc = nil
	nc.dec = nil
	return &nc
}

func (c *StreamCipher) Key() (key []byte, keyLen int) {
	return c.key, c.info.keyLen
}

func (c *StreamCipher) IV() ([]byte, int) {
	return c.iv, c.info.ivLen
}
