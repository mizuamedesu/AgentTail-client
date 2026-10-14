// SPDX-License-Identifier: GPL-3.0-or-later

package sshkeys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func fixture(t *testing.T) ([]byte, string) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return private.Seed(), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}
func TestInstalledIdentitiesAuthenticateOverSSH(t *testing.T) {
	seed, public := fixture(t)
	defer clear(seed)
	serverHome, clientHome := t.TempDir(), t.TempDir()
	authorized, err := InstallPublic(serverHome, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = InstallPublic(serverHome, public); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(authorized)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(raw, []byte(public)) != 1 {
		t.Fatal("duplicate authorization")
	}
	path, err := InstallPrivate(clientHome, uuid.NewString(), public, seed)
	if err != nil {
		t.Fatal(err)
	}
	rawPrivate, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rawPrivate)
	signer, err := ssh.ParsePrivateKey(rawPrivate)
	if err != nil {
		t.Fatal(err)
	}
	allowed, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		i, _ := os.Stat(path)
		if i.Mode().Perm() != 0600 {
			t.Fatal("private key permissions", i.Mode())
		}
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return nil, os.ErrPermission
		}
		return &ssh.Permissions{}, nil
	}}
	_, host, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, _ := ssh.NewSignerFromKey(host)
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			serverDone <- e
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		s, _, _, e := ssh.NewServerConn(conn, config)
		if e == nil {
			s.Close()
		}
		serverDone <- e
	}()
	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}
func TestPrivateNeverOverwritesAndRejectsMismatch(t *testing.T) {
	home := t.TempDir()
	seed, pub := fixture(t)
	id := uuid.NewString()
	path, err := InstallPrivate(home, id, pub, seed)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	defer clear(before)
	if _, err = InstallPrivate(home, id, pub, seed); err == nil {
		t.Fatal("overwrote private key")
	}
	after, _ := os.ReadFile(path)
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("existing identity changed")
	}
	_, other := fixture(t)
	if _, err = InstallPrivate(home, uuid.NewString(), other, seed); err == nil {
		t.Fatal("accepted wrong key")
	}
	if _, err = InstallPrivate(home, "urn:uuid:"+id, pub, seed); err == nil {
		t.Fatal("accepted a non-canonical ID as a filename")
	}
	if _, err = InstallPrivate(home, "../../outside", pub, seed); err == nil {
		t.Fatal("accepted path as ID")
	}
	if _, err = InstallPublic(home, pub+"\ncommand=evil"); err == nil {
		t.Fatal("accepted multiline key")
	}
}
func TestPublicPreservesExistingRestrictionsAndRefusesLinks(t *testing.T) {
	home := t.TempDir()
	_, pub := fixture(t)
	os.Mkdir(filepath.Join(home, ".ssh"), 0700)
	path := filepath.Join(home, ".ssh", "authorized_keys")
	content := []byte("# existing entries\nrestrict " + pub + " existing comment")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallPublic(home, pub); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(content, got) {
		t.Fatal("weakened existing key restrictions")
	}
	_, second := fixture(t)
	if _, err := InstallPublic(home, second); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if !bytes.HasPrefix(got, append(content, '\n')) {
		t.Fatal("lost existing authorizations")
	}
	if runtime.GOOS == "windows" {
		return
	}
	outside := filepath.Join(t.TempDir(), "unchanged")
	os.WriteFile(outside, []byte("sentinel"), 0600)
	os.Remove(path)
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallPublic(home, pub); err == nil {
		t.Fatal("followed authorized_keys symlink")
	}
	got, _ = os.ReadFile(outside)
	if string(got) != "sentinel" {
		t.Fatal("modified link target")
	}
}
