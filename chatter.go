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
	//	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	"time"
	//	"fmt" //un-comment if you want to do any debug printing.
)

const KeyRotationInterval = 24 * time.Hour

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
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
	LastRatchetTime   time.Time
}

type SessionState struct {
	RootChain        *SymmetricKey
	SendChain        *SymmetricKey
	ReceiveChain     *SymmetricKey
	MyDHRatchet      *KeyPair
	PartnerDHRatchet *PublicKey
	SendCounter      int
	ReceiveCounter   int
}

// Serialising and saving the session state
func (c *Chatter) SaveSessionState(partnerIdentity *PublicKey) (*SessionState, error) {
	session, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return nil, errors.New("can't save state: no session with specified partner")
	}
	return &SessionState{
		RootChain:        session.RootChain,
		SendChain:        session.SendChain,
		ReceiveChain:     session.ReceiveChain,
		MyDHRatchet:      session.MyDHRatchet,
		PartnerDHRatchet: session.PartnerDHRatchet,
		SendCounter:      session.SendCounter,
		ReceiveCounter:   session.ReceiveCounter,
	}, nil
}

// Restoring a session from a saved state
func (c *Chatter) RestoreSessionState(partnerIdentity *PublicKey, state *SessionState) error {
	c.Sessions[*partnerIdentity] = &Session{
		RootChain:         state.RootChain,
		SendChain:         state.SendChain,
		ReceiveChain:      state.ReceiveChain,
		MyDHRatchet:       state.MyDHRatchet,
		PartnerDHRatchet:  state.PartnerDHRatchet,
		SendCounter:       state.SendCounter,
		ReceiveCounter:    state.ReceiveCounter,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
	}
	return nil
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
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

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
// func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

// 	if _, exists := c.Sessions[*partnerIdentity]; !exists {
// 		return errors.New("don't have that session open to tear down")
// 	}

// 	delete(c.Sessions, *partnerIdentity)

// 	// TODO: your code here to zeroize remaining state

//		return nil
//	}
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {
	session, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return errors.New("can't end session: no open session with specified partner")
	}

	// Zeroize all keys in the session
	if session.RootChain != nil {
		session.RootChain.Zeroize()
	}
	if session.SendChain != nil {
		session.SendChain.Zeroize()
	}
	if session.ReceiveChain != nil {
		session.ReceiveChain.Zeroize()
	}

	// Clear cached receive keys for out-of-order message handling
	for _, key := range session.CachedReceiveKeys {
		key.Zeroize()
	}
	session.CachedReceiveKeys = nil

	// Remove the session from the active sessions map
	delete(c.Sessions, *partnerIdentity)

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("already have session open")
	}

	ephemeralKeyPair := GenerateKeyPair()

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       ephemeralKeyPair, //Storing Alice's ephemeral key
		PartnerDHRatchet:  partnerIdentity,  //Storing Bob's identity key (used in later DH exchanges)
		SendCounter:       0,                //Initialising the message counter for outgoing messages
		ReceiveCounter:    0,                //Initialising the message counter for incoming messages
		// Deriving RootChain, SendChain, and ReceiveChain later
	}

	// TODO: your code here

	return nil, errors.New("not implemented")
}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("already have session open")
	}

	//Generating Bob's ephemeral key pair for this session
	ephemeralKeyPair := GenerateKeyPair()

	//Calculating the initial root key (kroot1) using Alice's identity and ephemeral keys
	kroot1 := CombineKeys(
		DHCombine(partnerIdentity, &ephemeralKeyPair.PrivateKey),  // gA·b
		DHCombine(partnerEphemeral, &c.Identity.PrivateKey),       // ga·B
		DHCombine(partnerEphemeral, &ephemeralKeyPair.PrivateKey), // ga·b
	)

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       ephemeralKeyPair, //Storing Bob’s ephemeral key
		PartnerDHRatchet:  partnerEphemeral, //Storing Alice’s ephemeral key
		RootChain:         kroot1,           //Storing the derived root key
		SendCounter:       0,                //Initialising counters for messages
		ReceiveCounter:    0,
	}

	//Deriving an authentication key from kroot1 for Alice to verify
	authKey := kroot1.DeriveKey(HANDSHAKE_CHECK_LABEL)

	return &ephemeralKeyPair.PublicKey, authKey, nil
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake.The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("can't finalize session, not yet open")
	}

	session := c.Sessions[*partnerIdentity]

	//Calculating the initial root key (kroot1) using Bob's keys
	kroot1 := CombineKeys(
		DHCombine(partnerIdentity, &session.MyDHRatchet.PrivateKey),  // gA·b
		DHCombine(partnerEphemeral, &c.Identity.PrivateKey),          // ga·B
		DHCombine(partnerEphemeral, &session.MyDHRatchet.PrivateKey), // ga·b
	)

	//Storing the root key in the session
	session.RootChain = kroot1

	// Derive and return the authentication key for verification
	authKey := kroot1.DeriveKey(HANDSHAKE_CHECK_LABEL)
	return authKey, nil
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
// func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
// 	plaintext string) (*Message, error) {

// 	if _, exists := c.Sessions[*partnerIdentity]; !exists {
// 		return nil, errors.New("can't send message to partner with no open session")
// 	}

// 	session := c.Sessions[*partnerIdentity]
// 	messageKey := session.SendChain.DeriveKey(KEY_LABEL)
// 	iv := NewIV()
// 	ciphertext := messageKey.AuthenticatedEncrypt(plaintext, session.MyDHRatchet.Fingerprint(), iv)

// 	message := &Message{
// 		Sender:        &c.Identity.PublicKey,
// 		Receiver:      partnerIdentity,
// 		NextDHRatchet: &session.MyDHRatchet.PublicKey,
// 		Counter:       session.SendCounter,
// 		LastUpdate:    session.LastUpdate,
// 		Ciphertext:    ciphertext,
// 		IV:            iv,
// 	}
// 	session.SendCounter++

// 	//Ratcheting the send chain key by deriving the next send chain key
// 	session.SendChain = session.SendChain.DeriveKey(CHAIN_LABEL)

//		return message, errors.New("not implemented")
//	}
func (c *Chatter) SendMessage(partnerIdentity *PublicKey, plaintext string) (*Message, error) {
	session, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return nil, errors.New("can't send message to partner with no open session")
	}

	// Perform key rotation if 100 messages sent or if time interval has passed
	if session.SendCounter%100 == 0 || time.Since(session.LastRatchetTime) >= KeyRotationInterval {
		newDHRatchet := GenerateKeyPair()
		session.MyDHRatchet = newDHRatchet

		newRootKey := CombineKeys(
			DHCombine(session.PartnerDHRatchet, &session.MyDHRatchet.PrivateKey),
		)
		session.RootChain = newRootKey
		session.SendChain = newRootKey.DeriveKey(CHAIN_LABEL)
		session.ReceiveChain = newRootKey.DeriveKey(CHAIN_LABEL)
		session.LastRatchetTime = time.Now() // Update the last ratchet time
	}

	messageKey := session.SendChain.DeriveKey(KEY_LABEL)
	iv := NewIV()
	ciphertext := messageKey.AuthenticatedEncrypt(plaintext, session.MyDHRatchet.Fingerprint(), iv)

	message := &Message{
		Sender:        &c.Identity.PublicKey,
		Receiver:      partnerIdentity,
		NextDHRatchet: &session.MyDHRatchet.PublicKey,
		Counter:       session.SendCounter,
		LastUpdate:    session.LastUpdate,
		Ciphertext:    ciphertext,
		IV:            iv,
	}

	session.SendCounter++
	session.SendChain = session.SendChain.DeriveKey(CHAIN_LABEL)

	return message, nil
}

//PART 2
// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
// func (c *Chatter) ReceiveMessage(message *Message) (string, error) {
//     session, exists := c.Sessions[*message.Sender]
//     if !exists {
//         return "", errors.New("can't receive message from partner with no open session")
//     }

//     // Check if there's a new DH key from the sender
//     if message.NextDHRatchet != nil && message.NextDHRatchet != &session.PartnerDHRatchet {
//         session.PartnerDHRatchet = message.NextDHRatchet.Duplicate()
//         newRootKey := CombineKeys(
//             DHCombine(&session.PartnerDHRatchet, &session.MyDHRatchet.PrivateKey),
//         )
//         session.RootChain = newRootKey
//         session.SendChain = newRootKey.DeriveKey(CHAIN_LABEL)
//         session.ReceiveChain = newRootKey.DeriveKey(CHAIN_LABEL)
//     }

//     // Use a cached key if available
//     if cachedKey, ok := session.CachedReceiveKeys[message.Counter]; ok {
//         plaintext, err := cachedKey.AuthenticatedDecrypt(message.Ciphertext, message.Sender.Fingerprint(), message.IV)
//         if err == nil {
//             delete(session.CachedReceiveKeys, message.Counter)
//             return plaintext, nil
//         }
//     }

//     // Derive the message key from the receive chain
//     messageKey := session.ReceiveChain.DeriveKey(KEY_LABEL)
//     plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, message.Sender.Fingerprint(), message.IV)
//     if err != nil {
//         return "", err
//     }

//     // Cache the derived key for out-of-order handling
//     session.CachedReceiveKeys[message.Counter] = messageKey

//     session.ReceiveCounter++
//     session.ReceiveChain = session.ReceiveChain.DeriveKey(CHAIN_LABEL)

//     return plaintext, nil
// }

//PART 3
// func (c *Chatter) ReceiveMessage(message *Message) (string, error) {
// 	session, exists := c.Sessions[*message.Sender]
// 	if !exists {
// 		return "", errors.New("can't receive message from partner with no open session")
// 	}

// 	// Check if there's a new DH key from the sender
// 	if message.NextDHRatchet != nil && message.NextDHRatchet != session.PartnerDHRatchet {
// 		session.PartnerDHRatchet = message.NextDHRatchet.Duplicate()
// 		newRootKey := CombineKeys(
// 			DHCombine(session.PartnerDHRatchet, &session.MyDHRatchet.PrivateKey),
// 		)
// 		session.RootChain = newRootKey
// 		session.SendChain = newRootKey.DeriveKey(CHAIN_LABEL)
// 		session.ReceiveChain = newRootKey.DeriveKey(CHAIN_LABEL)
// 	}

// 	// Use a cached key if available
// 	if cachedKey, ok := session.CachedReceiveKeys[message.Counter]; ok {
// 		plaintext, err := cachedKey.AuthenticatedDecrypt(message.Ciphertext, message.Sender.Fingerprint(), message.IV)
// 		if err == nil {
// 			delete(session.CachedReceiveKeys, message.Counter)
// 			return plaintext, nil
// 		}
// 	}

// 	// Derive the message key from the receive chain
// 	messageKey := session.ReceiveChain.DeriveKey(KEY_LABEL)
// 	plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, message.Sender.Fingerprint(), message.IV)
// 	if err != nil {
// 		return "", err
// 	}

// 	// Cache the derived key for out-of-order handling
// 	session.CachedReceiveKeys[message.Counter] = messageKey

// 	session.ReceiveCounter++
// 	session.ReceiveChain = session.ReceiveChain.DeriveKey(CHAIN_LABEL)

// 	return plaintext, nil
// }

// PART 4
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {
	session, exists := c.Sessions[*message.Sender]
	if !exists {
		return "", errors.New("can't receive message: no open session with sender")
	}

	// Check for a new DH key and update if necessary
	if message.NextDHRatchet != nil && message.NextDHRatchet != session.PartnerDHRatchet {
		session.PartnerDHRatchet = message.NextDHRatchet.Duplicate()
		newRootKey := CombineKeys(
			DHCombine(session.PartnerDHRatchet, &session.MyDHRatchet.PrivateKey),
		)
		session.RootChain = newRootKey
		session.SendChain = newRootKey.DeriveKey(CHAIN_LABEL)
		session.ReceiveChain = newRootKey.DeriveKey(CHAIN_LABEL)
	}

	// Use a cached key if available
	if cachedKey, ok := session.CachedReceiveKeys[message.Counter]; ok {
		plaintext, err := cachedKey.AuthenticatedDecrypt(message.Ciphertext, message.Sender.Fingerprint(), message.IV)
		if err == nil {
			delete(session.CachedReceiveKeys, message.Counter)
			return plaintext, nil
		}
		return "", errors.New("decryption failed for cached key: possible tampering")
	}

	// Derive the message key from the receive chain
	messageKey := session.ReceiveChain.DeriveKey(KEY_LABEL)
	plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, message.Sender.Fingerprint(), message.IV)
	if err != nil {
		return "", errors.New("decryption failed: possible tampering")
	}

	// Cache the derived key for out-of-order handling
	session.CachedReceiveKeys[message.Counter] = messageKey

	session.ReceiveCounter++
	session.ReceiveChain = session.ReceiveChain.DeriveKey(CHAIN_LABEL)

	return plaintext, nil
}
