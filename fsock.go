/*
fsock.go is released under the MIT License <http://www.opensource.org/licenses/mit-license.php
Copyright (C) ITsysCOM. All Rights Reserved.

Provides FreeSWITCH socket communication.

*/

package fsock

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	FS        *FSock // Used to share FS connection via package globals
	DelayFunc func() func() int

	ErrConnectionPoolTimeout = errors.New("ConnectionPool timeout")
)

func init() {
	DelayFunc = fib
}

// Connects to FS and starts buffering input
func NewFSock(fsaddr, fspaswd string, reconnects int, eventHandlers map[string][]func(string, int), eventFilters map[string][]string,
	l *log.Logger, connIdx int) (fsock *FSock, err error) {
	// Default logger to stdout
	if l == nil {
		l = log.New(os.Stdout, "[FSock] ", log.Ldate|log.Ltime|log.Lshortfile)
	}

	fsock = &FSock{
		fsMutex:         new(sync.RWMutex),
		connIdx:         connIdx,
		fsAddress:       fsaddr,
		fsPassword:      fspaswd,
		eventHandlers:   eventHandlers,
		eventFilters:    eventFilters,
		backgroundChans: make(map[string]chan string),
		cmdChan:         make(chan string),
		reconnects:      reconnects,
		delayFunc:       DelayFunc(),
		logger:          l,
	}
	if err = fsock.Connect(); err != nil {
		return nil, err
	}
	return
}

// Connection to FreeSWITCH Socket
type FSock struct {
	conn            net.Conn
	fsMutex         *sync.RWMutex
	connIdx         int // Indetifier for the component using this instance of FSock, optional
	buffer          *bufio.Reader
	fsAddress       string
	fsPassword      string
	eventHandlers   map[string][]func(string, int) // eventStr, connId
	eventFilters    map[string][]string
	backgroundChans map[string]chan string
	cmdChan         chan string
	reconnects      int
	delayFunc       func() int
	stopReadEvents  chan struct{} //Keep a reference towards forkedReadEvents so we can stop them whenever necessary
	errReadEvents   chan error
	logger          *log.Logger
}

// Connect or reconnect
func (f *FSock) Connect() error {
	if f.stopReadEvents != nil {
		close(f.stopReadEvents) // we have read events already processing, request stop
	}
	// Reinit readEvents channels so we avoid concurrency issues between goroutines
	f.stopReadEvents = make(chan struct{})
	f.errReadEvents = make(chan error)
	return f.connect()

}

func (f *FSock) connect() error {
	if f.Connected() {
		_ = f.Disconnect()
	}

	conn, err := net.Dial("tcp", f.fsAddress)
	if err != nil {
		if f.logger != nil {
			f.logger.Println(fmt.Sprintf("<FSock> Attempt to connect to FreeSWITCH, received: %s", err.Error()))
		}
		return err
	}
	f.fsMutex.Lock()
	f.conn = conn
	f.fsMutex.Unlock()
	if f.logger != nil {
		f.logger.Println("<FSock> Successfully connected to FreeSWITCH!")
	}
	// Connected, init buffer, auth and subscribe to desired events and filters
	f.fsMutex.RLock()
	f.buffer = bufio.NewReaderSize(f.conn, 8192) // reinit buffer
	f.fsMutex.RUnlock()

	if authChg, err := f.readHeaders(); err != nil || !strings.Contains(authChg, "auth/request") {
		return errors.New("no auth challenge received")
	} else if errAuth := f.auth(); errAuth != nil { // Auth did not succeed
		return errAuth
	}
	// Subscribe to events handled by event handlers
	if err := f.events(getMapKeys(f.eventHandlers)); err != nil {
		return err
	}

	if err := f.filterEvents(f.eventFilters); err != nil {
		return err
	}
	go f.readEvents() // Fork read events in it's own goroutine
	return nil
}

// Connected checks if socket connected. Can be extended with pings
func (f *FSock) Connected() (ok bool) {
	f.fsMutex.RLock()
	ok = f.conn != nil
	f.fsMutex.RUnlock()
	return
}

// Disconnects from socket
func (f *FSock) Disconnect() (err error) {
	f.fsMutex.Lock()
	if f.conn != nil {
		if f.logger != nil {
			f.logger.Println("<FSock> Disconnecting from FreeSWITCH!")
		}
		err = f.conn.Close()
		f.conn = nil
	}
	f.fsMutex.Unlock()
	return
}

// If not connected, attempt reconnect if allowed
func (f *FSock) ReconnectIfNeeded() (err error) {
	if f.Connected() { // No need to reconnect
		return nil
	}
	for i := 0; f.reconnects == -1 || i < f.reconnects; i++ { // Maximum reconnects reached, -1 for infinite reconnects
		if err = f.connect(); err == nil && f.Connected() {
			f.delayFunc = DelayFunc() // Reset the reconnect delay
			break                     // No error or unrelated to connection
		}
		time.Sleep(time.Duration(f.delayFunc()) * time.Second)
	}
	if err == nil && !f.Connected() {
		return errors.New("not connected to FreeSWITCH")
	}
	return err // nil or last error in the loop
}

func (f *FSock) send(cmd string) {
	f.fsMutex.RLock()
	// fmt.Fprint(f.conn, cmd)
	w, err := f.conn.Write([]byte(cmd))
	if err != nil {
		if f.logger != nil {
			f.logger.Println(fmt.Sprintf("<FSock> Cannot write command to socket <%s>", err.Error()))
		}
		return
	}
	if w == 0 {
		if f.logger != nil {
			f.logger.Println("<FSock> Cannot write command to socket: " + cmd)
		}
		return
	}
	f.fsMutex.RUnlock()
}

// Auth to FS
func (f *FSock) auth() error {
	f.send(fmt.Sprintf("auth %s\n\n", f.fsPassword))
	if rply, err := f.readHeaders(); err != nil {
		return err
	} else if !strings.Contains(rply, "Reply-Text: +OK accepted") {
		return fmt.Errorf("unexpected auth reply received: <%s>", rply)
	}
	return nil
}

func (f *FSock) sendCmd(cmd string) (rply string, err error) {
	if err = f.ReconnectIfNeeded(); err != nil {
		return "", err
	}
	cmd = fmt.Sprintf("%s\n", cmd)
	f.send(cmd)
	rply = <-f.cmdChan
	if strings.Contains(rply, "-ERR") {
		return "", errors.New(strings.TrimSpace(rply))
	}
	return rply, nil
}

// Generic proxy for commands
func (f *FSock) SendCmd(cmdStr string) (string, error) {
	return f.sendCmd(cmdStr + "\n")
}

func (f *FSock) SendCmdWithArgs(cmd string, args map[string]string, body string) (string, error) {
	for k, v := range args {
		cmd += fmt.Sprintf("%s: %s\n", k, v)
	}
	if len(body) != 0 {
		cmd += fmt.Sprintf("\n%s\n", body)
	}
	return f.sendCmd(cmd)
}

// Send API command
func (f *FSock) SendApiCmd(cmdStr string) (string, error) {
	return f.sendCmd("api " + cmdStr + "\n")
}

// Send BGAPI command
func (f *FSock) SendBgapiCmd(cmdStr string) (out chan string, err error) {
	jobUuid := genUUID()
	out = make(chan string)

	f.fsMutex.Lock()
	f.backgroundChans[jobUuid] = out
	f.fsMutex.Unlock()

	_, err = f.sendCmd(fmt.Sprintf("bgapi %s\nJob-UUID:%s\n", cmdStr, jobUuid))
	if err != nil {
		return nil, err
	}
	return
}

// SendMsgCmdWithBody command
func (f *FSock) SendMsgCmdWithBody(uuid string, cmdargs map[string]string, body string) error {
	if len(cmdargs) == 0 {
		return errors.New("need command arguments")
	}
	_, err := f.SendCmdWithArgs(fmt.Sprintf("sendmsg %s\n", uuid), cmdargs, body)
	return err
}

// SendMsgCmd command
func (f *FSock) SendMsgCmd(uuid string, cmdargs map[string]string) error {
	return f.SendMsgCmdWithBody(uuid, cmdargs, "")
}

// SendEventWithBody command
func (f *FSock) SendEventWithBody(eventSubclass string, eventParams map[string]string, body string) (string, error) {
	// Event-Name is overrided to CUSTOM by FreeSWITCH,
	// so we use Event-Subclass instead
	eventParams["Event-Subclass"] = eventSubclass
	return f.SendCmdWithArgs(fmt.Sprintf("sendevent %s\n", eventSubclass), eventParams, body)
}

// SendEvent command
func (f *FSock) SendEvent(eventSubclass string, eventParams map[string]string) (string, error) {
	return f.SendEventWithBody(eventSubclass, eventParams, "")
}

// ReadEvents reads events from socket, attempt reconnect if disconnected
func (f *FSock) ReadEvents() (err error) {
	var opened bool
	for {
		if err, opened = <-f.errReadEvents; !opened {
			return nil
		} else if err == io.EOF { // Disconnected, try reconnect
			if err = f.ReconnectIfNeeded(); err != nil {
				break
			}
		}
	}
	return err
}

func (f *FSock) LocalAddr() net.Addr {
	if !f.Connected() {
		return nil
	}
	return f.conn.LocalAddr()
}

// Reads headers until delimiter reached
func (f *FSock) readHeaders() (header string, err error) {
	bytesRead := make([]byte, 0)
	var readLine []byte

	for {
		readLine, err = f.buffer.ReadBytes('\n')
		if err != nil {
			if f.logger != nil {
				f.logger.Println(fmt.Sprintf("<FSock> Error reading headers: <%s>", err.Error()))
			}
			_ = f.Disconnect()
			return "", err
		}
		// No Error, add received to localread buffer
		if len(bytes.TrimSpace(readLine)) == 0 {
			break
		}
		bytesRead = append(bytesRead, readLine...)
	}
	return string(bytesRead), nil
}

// Reads the body from buffer, ln is given by content-length of headers
func (f *FSock) readBody(noBytes int) (body string, err error) {
	bytesRead := make([]byte, noBytes)
	var readByte byte

	for i := 0; i < noBytes; i++ {
		if readByte, err = f.buffer.ReadByte(); err != nil {
			if f.logger != nil {
				f.logger.Println(fmt.Sprintf("<FSock> Error reading message body: <%s>", err.Error()))
			}
			_ = f.Disconnect()
			return "", err
		}
		// No Error, add received to local read buffer
		bytesRead[i] = readByte
	}
	return string(bytesRead), nil
}

// Event is made out of headers and body (if present)
func (f *FSock) readEvent() (header string, body string, err error) {
	var cl int

	if header, err = f.readHeaders(); err != nil {
		return "", "", err
	}
	if !strings.Contains(header, "Content-Length") { //No body
		return header, "", nil
	}
	if cl, err = strconv.Atoi(headerVal(header, "Content-Length")); err != nil {
		return "", "", errors.New("cannot extract content length")
	}
	if body, err = f.readBody(cl); err != nil {
		return "", "", err
	}
	return
}

// Read events from network buffer, stop when exitChan is closed, report on errReadEvents on error and exit
// Receive exitChan and errReadEvents as parameters so we avoid concurrency on using self.
func (f *FSock) readEvents() {
	for {
		select {
		case <-f.stopReadEvents:
			return
		default: // Unlock waiting here
		}
		hdr, body, err := f.readEvent()
		if err != nil {
			f.errReadEvents <- err
			return
		}
		if strings.Contains(hdr, "api/response") {
			f.cmdChan <- body
		} else if strings.Contains(hdr, "command/reply") {
			f.cmdChan <- headerVal(hdr, "Reply-Text")
		} else if body != "" { // We got a body, could be event, try dispatching it
			f.dispatchEvent(body)
		}
	}
}

// Subscribe to events
func (f *FSock) events(events []string) error {
	// if len(events) == 0 {
	// 	return nil
	// }
	eventsCmd := "event json"
	customEvents := ""
	for _, ev := range events {
		if ev == "ALL" {
			eventsCmd = "event json all"
			break
		}
		if strings.HasPrefix(ev, "CUSTOM") {
			customEvents += ev[6:] // will capture here also space between CUSTOM and event
			continue
		}
		eventsCmd += " " + ev
	}
	if eventsCmd != "event json all" {
		eventsCmd += " BACKGROUND_JOB" // For bgapi
		if len(customEvents) != 0 {    // Add CUSTOM events subscribing in the end otherwise unexpected events are received
			eventsCmd += " " + "CUSTOM" + customEvents
		}
	}
	eventsCmd += "\n\n"
	f.send(eventsCmd)
	if rply, err := f.readHeaders(); err != nil {
		return err
	} else if !strings.Contains(rply, "Reply-Text: +OK") {
		_ = f.Disconnect()
		return fmt.Errorf("unexpected events-subscribe reply received: <%s>", rply)
	}
	return nil
}

// Enable filters
func (f *FSock) filterEvents(filters map[string][]string) error {
	if len(filters) == 0 {
		return nil
	}
	filters["Event-Name"] = append(filters["Event-Name"], "BACKGROUND_JOB") // for bgapi
	for hdr, vals := range filters {
		for _, val := range vals {
			cmd := "filter " + hdr + " " + val + "\n\n"
			f.send(cmd)
			if rply, err := f.readHeaders(); err != nil {
				return err
			} else if !strings.Contains(rply, "Reply-Text: +OK") {
				return fmt.Errorf("unexpected filter-events reply received: <%s>", rply)
			}
		}
	}
	return nil
}

// Dispatch events to handlers in async mode
func (f *FSock) dispatchEvent(event string) {
	eventName := headerVal(event, "Event-Name")
	if eventName == "BACKGROUND_JOB" { // for bgapi BACKGROUND_JOB
		go f.doBackgroundJob(event)
		return
	}

	if eventName == "CUSTOM" {
		eventSubclass := headerVal(event, "Event-Subclass")
		if len(eventSubclass) != 0 {
			eventName += " " + urlDecode(eventSubclass)
		}
	}

	for _, handleName := range []string{eventName, "ALL"} {
		if _, hasHandlers := f.eventHandlers[handleName]; hasHandlers {
			// We have handlers, dispatch to all of them
			for _, handlerFunc := range f.eventHandlers[handleName] {
				go handlerFunc(event, f.connIdx)
			}
			return
		}
	}
	if f.logger != nil {
		fmt.Printf("No dispatcher, event name: %s, handlers: %+v\n", eventName, f.eventHandlers)
		f.logger.Println(fmt.Sprintf("<FSock> No dispatcher for event: <%+v>", event))
	}
}

// bgapi event listen function
func (f *FSock) doBackgroundJob(event string) { // add mutex protection
	evMap := EventToMap(event)
	jobUuid, has := evMap["Job-UUID"]
	if !has {
		if f.logger != nil {
			f.logger.Println("<FSock> BACKGROUND_JOB with no Job-UUID")
		}
		return
	}

	var out chan string
	f.fsMutex.RLock()
	out, has = f.backgroundChans[jobUuid]
	f.fsMutex.RUnlock()
	if !has {
		if f.logger != nil {
			f.logger.Println(fmt.Sprintf("<FSock> BACKGROUND_JOB with UUID %s lost!", jobUuid))
		}
		return // not a requested bgapi
	}

	f.fsMutex.Lock()
	delete(f.backgroundChans, jobUuid)
	f.fsMutex.Unlock()

	out <- evMap[EventBodyTag]
}

// Instantiates a new FSockPool
func NewFSockPool(maxFSocks int, fsaddr, fspasswd string, reconnects int, maxWaitConn time.Duration,
	eventHandlers map[string][]func(string, int), eventFilters map[string][]string, l *log.Logger, connIdx int) (*Pool, error) {
	pool := &Pool{
		connIdx:       connIdx,
		fsAddr:        fsaddr,
		fsPasswd:      fspasswd,
		reconnects:    reconnects,
		maxWaitConn:   maxWaitConn,
		eventHandlers: eventHandlers,
		eventFilters:  eventFilters,
		logger:        l,
		allowedConns:  make(chan struct{}, maxFSocks),
		fSocks:        make(chan *FSock, maxFSocks),
	}
	for i := 0; i < maxFSocks; i++ {
		pool.allowedConns <- struct{}{} // Empty initiate so we do not need to wait later when we pop
	}
	return pool, nil
}

// Connection handler for commands sent to FreeSWITCH
type Pool struct {
	connIdx       int
	fsAddr        string
	fsPasswd      string
	reconnects    int
	eventHandlers map[string][]func(string, int)
	eventFilters  map[string][]string
	logger        *log.Logger
	allowedConns  chan struct{} // Will be populated with members allowed
	fSocks        chan *FSock   // Keep here reference towards the list of opened sockets
	maxWaitConn   time.Duration // Maximum duration to wait for a connection to be returned by Pop
}

func (p *Pool) PopFSock() (fsock *FSock, err error) {
	if p == nil {
		return nil, errors.New("unconfigured ConnectionPool")
	}
	if len(p.fSocks) != 0 { // Select directly if available, so we avoid randomness of selection
		fsock = <-p.fSocks
		return fsock, nil
	}
	select { // No fsock available in the pool, wait for first one showing up
	case fsock = <-p.fSocks:
	case <-p.allowedConns:
		fsock, err = NewFSock(p.fsAddr, p.fsPasswd, p.reconnects, p.eventHandlers, p.eventFilters, p.logger, p.connIdx)
		if err != nil {
			return nil, err
		}
		return fsock, nil
	case <-time.After(p.maxWaitConn):
		return nil, ErrConnectionPoolTimeout
	}
	return fsock, nil
}

func (p *Pool) PushFSock(fsk *FSock) {
	if p == nil { // Did not initialize the pool
		return
	}
	if fsk == nil || !fsk.Connected() {
		p.allowedConns <- struct{}{}
		return
	}
	p.fSocks <- fsk
}
