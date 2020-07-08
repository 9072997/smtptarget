/*
Package smtptarget offers a replacement for common uses of smtp.SendMail()
with support for persistent connections. In the name of simplicity it only
supports plain auth protected by TLS. It is thread safe, but operations will
not be executed in parallell.
*/
package smtptarget

import (
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"os"
	"sync"
	"time"
)

// Target represents a destination to which mail may be sent
type Target struct {
	addr     string
	username string
	password string
	timeout  time.Duration

	client           *smtp.Client
	mutex            sync.Mutex
	lastUse          time.Time
	possibleTimeout  chan interface{}
	possibleTimeouts sync.WaitGroup
	closed           bool
}

// New creates a new Target to which you can send mail. host should be a
// host and port in the format "smtp.example.com:587". Username and password
// are required. Anonymous authentication is not supported. timeout is how
// long the connection will be allowed to sit idle before it is
// disconnected. It will automatically re-connect next time you call
// SendMail().
func New(addr, username, password string, timeout time.Duration) *Target {
	t := Target{
		addr:            addr,
		username:        username,
		password:        password,
		timeout:         timeout,
		possibleTimeout: make(chan interface{}),
	}

	// start a thread that will watch for possible timeouts
	go func() {
		for {
			// if the channel was closed, end the thread
			_, channelOpen := <-t.possibleTimeout
			if !channelOpen {
				return
			}

			// we can't get a good idea of last use if we are in the middle
			// of sending an email
			t.mutex.Lock()

			idleTime := time.Now().Sub(t.lastUse)
			if idleTime > t.timeout {
				_ = t.disconnect()
			}

			t.mutex.Unlock()
		}
	}()

	return &t
}

// Close the connection to the SMTP server and end the possibleTimeout
// watcher thread. The Target cannot be used after this. You must make a new
// one.
func (t *Target) Close() error {
	// can't be sending mail while we disconnect
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// don't try to close a channel twice
	if t.closed {
		return errors.New("Target is already closed")
	}

	// so we know the possibleTimeout watcher is dead or dieing
	t.closed = true

	// register shutdown for the possibleTimeout watcher
	go func() {
		// don't close the channel before all timeouts are finished comeing
		// in, or it will cause a panic next time one does.
		t.possibleTimeouts.Wait()
		close(t.possibleTimeout)
	}()

	return t.disconnect()
}

// SendMail works like smtp.SendMail() except that it uses the connection
// from the Target. It will first re-establish the connection if the
// connection is unhealthy or not connected.
func (t *Target) SendMail(from string, to []string, msg []byte) error {
	// can't send more than one message at a time
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// if the target is closed there is no possibleTimeout watcher, so we
	// don't want to open a new connection
	if t.closed {
		return errors.New("Target is closed")
	}

	// ensure the client is connected and in a known state
	err := t.reset()
	if err != nil {
		return err
	}

	// set from and to addresses
	err = t.client.Mail(from)
	if err != nil {
		return err
	}
	for _, addr := range to {
		err = t.client.Rcpt(addr)
		if err != nil {
			return err
		}
	}

	// send message data
	dataWriter, err := t.client.Data()
	if err != nil {
		return err
	}
	_, err = dataWriter.Write(msg)
	if err != nil {
		return err
	}
	err = dataWriter.Close()
	if err != nil {
		return err
	}

	// reset the idle disconnect timer
	t.lastUse = time.Now()
	// register a possible timeout some time from now
	t.possibleTimeouts.Add(1)
	go func() {
		<-time.After(t.timeout)
		t.possibleTimeout <- nil
		t.possibleTimeouts.Done()
	}()

	return nil
}

// ensure there is a functioning connection to the SMTP server and that it
// is in a known state
// NOTE: this is NOT threadsafe
func (t *Target) reset() (err error) {
	switch {
	// we have a connection, but something is wrong with it
	case t.client != nil && t.client.Noop() != nil:
		// disconnect ignoreing errors
		_ = t.disconnect()
		fallthrough
	// we don't have a connection
	case t.client == nil:
		// open the connection to the server
		t.client, err = smtp.Dial(t.addr)
		if err != nil {
			return err
		}

		// identify ourselves
		localHost, err := os.Hostname()
		if err != nil {
			localHost = "localhost"
		}
		err = t.client.Hello(localHost)
		if err != nil {
			return err
		}

		// start TLS (encryption)
		serverHost, _, err := net.SplitHostPort(t.addr)
		if err != nil {
			return err
		}
		err = t.client.StartTLS(&tls.Config{ServerName: serverHost})
		if err != nil {
			return err
		}

		// authenticate
		auth := smtp.PlainAuth("", t.username, t.password, serverHost)
		err = t.client.Auth(auth)
		if err != nil {
			return err
		}
	// we have a working connection, but we don't know what state it is in
	default:
		// reset to a known state
		err := t.client.Reset()
		if err != nil {
			return err
		}
	}
	return nil
}

// close the connection to the SMTP server
// NOTE: this is NOT threadsafe
func (t *Target) disconnect() error {
	if t.client == nil {
		return nil
	}
	err := t.client.Quit()
	_ = t.client.Close()
	t.client = nil
	return err
}
