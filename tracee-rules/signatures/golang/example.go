package main

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

var ExportedSignatures []types.Signature = []types.Signature{
	&counter{target: 2},
	&counter{target: 3},
}

type counter struct {
	cb     types.SignatureHandler
	target int
	count  int
}

func (sig *counter) Init(cb types.SignatureHandler) error {
	sig.cb = cb
	sig.count = 0
	return nil
}

func (sig *counter) GetMetadata() types.SignatureMetadata {
	return types.SignatureMetadata{
		Name: "count to " + strconv.Itoa(sig.target),
	}
}

func (sig *counter) GetSelectedEvents() []types.SignatureEventSelector {
	return []types.SignatureEventSelector{{
		Source: "tracee",
		//Name:   "execve",
	}}
}

func (sig *counter) OnEvent(e types.Event) error {
	ee, ok := e.(types.TraceeEvent)
	if !ok {
		return fmt.Errorf("invalid event")
	}

	if ee.ArgsNum > 0 && filepath.Base(ee.Args[0].Value.(string)) == "yo" {
		sig.count++
	}
	if sig.count == sig.target {
		sig.cb(types.Finding{
			Data: []types.FindingData{{
				Type: "count",
				Properties: map[string]interface{}{
					"count":    sig.count,
					"severity": "HIGH",
				}}},
			Context:   e,
			Signature: sig,
		})
		sig.count = 0
	}
	return nil
}

func (sig *counter) OnSignal(signal types.Signal) error {
	source, sigcomplete := signal.(types.SignalSourceComplete)
	if sigcomplete && source == "tracee" {
		sig.cb(types.Finding{
			Data: []types.FindingData{{
				Type: "message",
				Properties: map[string]interface{}{
					"message": "done",
				},
			}}})
	}
	return nil
}
