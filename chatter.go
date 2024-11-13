// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const HANDSHAKE_CHECK_LABEL byte = 0x11
const ROOT_LABEL = 0x22
const CHAIN_LABEL = 0x33
const KEY_LABEL = 0x44

type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
}

type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}
	return buf
}

func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {
	session, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return errors.New("Don't have that session open to tear down")
	}

	if session.RootChain != nil {
		session.RootChain.Key = nil
	}
	if session.SendChain != nil {
		session.SendChain.Key = nil
	}
	if session.ReceiveChain != nil {
		session.ReceiveChain.Key = nil
	}
	for k := range session.CachedReceiveKeys {
		session.CachedReceiveKeys[k].Key = nil
	}
	session.SendCounter = 0
	session.ReceiveCounter = 0
	delete(c.Sessions, *partnerIdentity)
	return nil
}

func ComputeSharedSecret(privateKey *PrivateKey, publicKey *PublicKey) ([]byte, error) {
	privateKeyBytes := privateKey.Key
	if len(privateKeyBytes) == 0 {
		return nil, errors.New("empty private key bytes")
	}

	publicKeyBytes := append(publicKey.X.Bytes(), publicKey.Y.Bytes()...)
	if len(publicKeyBytes) == 0 {
		return nil, errors.New("empty public key bytes")
	}

	ecdhPrivateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDH private key: %v", err)
	}

	ecdhPublicKey, err := ecdh.P256().NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDH public key: %v", err)
	}

	sharedSecret, err := ecdhPrivateKey.ECDH(ecdhPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %v", err)
	}

	return sharedSecret, nil
}

func DeriveSymmetricKey(sharedSecret []byte, salt []byte, info []byte) (*SymmetricKey, error) {
	hkdf := hkdf.New(sha256.New, sharedSecret, salt, info)
	key := make([]byte, 32)

	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}

	return &SymmetricKey{Key: key}, nil
}

func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {
	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	ephemeralKey := GenerateKeyPair()

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       ephemeralKey,
		PartnerDHRatchet:  partnerIdentity,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0,
		ReceiveCounter:    0,
		LastUpdate:        0,
	}

	return &ephemeralKey.PublicKey, nil
}

func (c *Chatter) ReturnHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {
	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	ephemeralKey := GenerateKeyPair()

	sharedSecret1Bytes, _ := ComputeSharedSecret(&c.Identity.PrivateKey, partnerEphemeral)
	sharedSecret2Bytes, _ := ComputeSharedSecret(&ephemeralKey.PrivateKey, partnerIdentity)

	sharedSecret1 := &SymmetricKey{Key: sharedSecret1Bytes}
	sharedSecret2 := &SymmetricKey{Key: sharedSecret2Bytes}

	rootKey := CombineKeys(sharedSecret1, sharedSecret2)
	checkKey := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	c.Sessions[*partnerIdentity] = &Session{
		MyDHRatchet:       ephemeralKey,
		PartnerDHRatchet:  partnerEphemeral,
		RootChain:         rootKey,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		SendCounter:       0,
		ReceiveCounter:    0,
		LastUpdate:        0,
	}

	return &ephemeralKey.PublicKey, checkKey, nil
}

func (c *Chatter) FinalizeHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*SymmetricKey, error) {
	session, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	sharedSecret1Bytes, _ := ComputeSharedSecret(&c.Identity.PrivateKey, partnerEphemeral)
	sharedSecret2Bytes, _ := ComputeSharedSecret(&session.MyDHRatchet.PrivateKey, partnerIdentity)

	sharedSecret1 := &SymmetricKey{Key: sharedSecret1Bytes}
	sharedSecret2 := &SymmetricKey{Key: sharedSecret2Bytes}

	rootKey := CombineKeys(sharedSecret1, sharedSecret2)
	checkKey := rootKey.DeriveKey(HANDSHAKE_CHECK_LABEL)

	session.RootChain = rootKey

	return checkKey, nil
}

func (c *Chatter) SendMessage(partnerIdentity *PublicKey, plaintext string) (*Message, error) {
	session, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return nil, errors.New("can't send message to partner with no open session")
	}

	if session.SendCounter%100 == 0 {
		newDHRatchet := GenerateKeyPair()
		session.MyDHRatchet = newDHRatchet

		sharedKey := DHCombine(session.PartnerDHRatchet, &session.MyDHRatchet.PrivateKey)
		session.RootChain = CombineKeys(session.RootChain.DeriveKey(ROOT_LABEL), sharedKey)

		session.SendChain = session.RootChain.DeriveKey(CHAIN_LABEL)
		session.ReceiveChain = session.RootChain.DeriveKey(CHAIN_LABEL)
	}

	messageKey := session.SendChain.DeriveKey(KEY_LABEL)
	iv := NewIV()

	message := &Message{
		Sender:        &c.Identity.PublicKey,
		Receiver:      partnerIdentity,
		NextDHRatchet: &session.MyDHRatchet.PublicKey,
		Counter:       session.SendCounter,
		LastUpdate:    session.LastUpdate,
	}
	additionalData := message.EncodeAdditionalData()

	ciphertext := messageKey.AuthenticatedEncrypt(plaintext, additionalData, iv)

	message.Ciphertext = ciphertext
	message.IV = iv

	session.SendCounter++
	session.SendChain = session.SendChain.DeriveKey(CHAIN_LABEL)

	return message, nil
}

func (c *Chatter) ReceiveMessage(message *Message) (string, error) {
	session, exists := c.Sessions[*message.Sender]
	if !exists {
		return "", errors.New("can't receive message from partner with no open session")
	}

	if message.NextDHRatchet != nil && message.NextDHRatchet != session.PartnerDHRatchet {
		oldRootChain := session.RootChain

		session.PartnerDHRatchet = message.NextDHRatchet.Duplicate()
		sharedKey := DHCombine(session.PartnerDHRatchet, &session.MyDHRatchet.PrivateKey)
		session.RootChain = CombineKeys(session.RootChain.DeriveKey(ROOT_LABEL), sharedKey)

		session.ReceiveChain = session.RootChain.DeriveKey(CHAIN_LABEL)
		session.SendChain = session.RootChain.DeriveKey(CHAIN_LABEL)

		defer func() {
			if err := recover(); err != nil {
				session.RootChain = oldRootChain
			}
		}()
	}

	additionalData := message.EncodeAdditionalData()

	messageKey := session.ReceiveChain.DeriveKey(KEY_LABEL)
	plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, additionalData, message.IV)
	if err != nil {
		return "", err
	}

	session.ReceiveCounter++
	session.ReceiveChain = session.ReceiveChain.DeriveKey(CHAIN_LABEL)

	return plaintext, nil
}
