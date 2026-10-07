// SPDX-License-Identifier: MIT

// Command lws-driver-adapter-go is the Go adapter of the lws-client driver: it runs the
// operations of driver/PROTOCOL.md (lws-driver/1) with the lws-client of ../../../go. It reads
// one JSON request per line on stdin and writes one JSON response per line on stdout; logs go
// to stderr.
//
// Build: go build -o bin/lws-driver-adapter-go .
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"

	lws "github.com/ebremer/lws-client/go"
)

const library = "lws-client-go/" + lws.Version

type helloJSON struct {
	Hello struct {
		Protocol   string   `json:"protocol"`
		Language   string   `json:"language"`
		Library    string   `json:"library"`
		Operations []string `json:"operations"`
	} `json:"hello"`
}

type okJSON struct {
	ID     json.RawMessage `json:"id,omitempty"`
	OK     bool            `json:"ok"`
	Result any             `json:"result"`
}

type failedJSON struct {
	ID    json.RawMessage `json:"id,omitempty"`
	OK    bool            `json:"ok"`
	Error errorJSON       `json:"error"`
}

// out is stdout: protocol messages only, one per line, flushed after every line.
var out = bufio.NewWriter(os.Stdout)

// encode serializes v as one line of JSON (the encoder escapes newlines inside strings).
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func write(v any, id json.RawMessage) {
	line, err := encode(v)
	if err != nil {
		log.Printf("encoding a response: %v", err)
		line, _ = encode(failedJSON{ID: id, Error: errorJSON{Kind: "InternalError", Message: "encoding the response: " + err.Error()}})
	}
	if _, err := out.Write(line); err == nil {
		err = out.Flush()
	}
	if err != nil {
		log.Printf("writing to stdout: %v", err)
		os.Exit(1)
	}
}

func failed(id json.RawMessage, err error) {
	write(failedJSON{ID: id, Error: errorResult(err)}, id)
}

// run runs an operation, turning a panic into an InternalError so that the adapter keeps running.
func run(a *adapter, op operation, x args) (result any, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic: %v\n%s", r, debug.Stack())
			err = &adapterError{kind: "InternalError", message: fmt.Sprintf("panic: %v", r)}
		}
	}()
	return op(a, x)
}

// handle answers one request line; it reports whether the request was shutdown.
func handle(a *adapter, ops map[string]operation, line []byte) bool {
	if !json.Valid(line) {
		failed(json.RawMessage("null"), invalid("the request is not JSON"))
		return false
	}
	request, ok := objectOf(line)
	if !ok {
		failed(json.RawMessage("null"), invalid("the request is not a JSON object"))
		return false
	}
	id := request["id"]
	var name string
	if raw, ok := request.raw("op"); ok {
		_ = json.Unmarshal(raw, &name)
	}
	op, ok := ops[name]
	if !ok {
		failed(id, &adapterError{kind: "Unsupported", message: fmt.Sprintf("unknown operation '%s'", name)})
		return false
	}
	x := args{}
	if raw, ok := request.raw("args"); ok {
		if x, ok = objectOf(raw); !ok {
			failed(id, invalid("args must be an object"))
			return name == "shutdown"
		}
	}
	result, err := run(a, op, x)
	if err != nil {
		failed(id, err)
	} else {
		write(okJSON{ID: id, OK: true, Result: result}, id)
	}
	return name == "shutdown"
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("lws-driver-adapter-go: ")
	log.SetOutput(os.Stderr)

	ops := map[string]operation{}
	var hello helloJSON
	hello.Hello.Protocol = "lws-driver/1"
	hello.Hello.Language = "go"
	hello.Hello.Library = library
	hello.Hello.Operations = []string{}
	for _, o := range operations {
		ops[o.name] = o.run
		hello.Hello.Operations = append(hello.Hello.Operations, o.name)
	}

	// Before the first configure, operations use a client with no authenticator.
	a := &adapter{client: lws.NewClient()}

	write(hello, nil)
	in := bufio.NewReaderSize(os.Stdin, 1<<16)
	for {
		line, err := in.ReadBytes('\n')
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			if handle(a, ops, trimmed) {
				break
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("reading stdin: %v", err)
			}
			break
		}
	}
	os.Exit(0)
}
