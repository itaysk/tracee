package engine

import (
	"log"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

type Engine struct {
	signatures      map[types.Signature]chan types.Event
	signaturesIndex map[types.SignatureEventSelector][]types.Signature
	inputs          sources
	output          chan types.Finding
}

type sources struct {
	tracee chan types.Event
}

func NewEngine(sigs []types.Signature, traceeSource chan types.Event, output chan types.Finding) Engine {
	engine := Engine{}
	engine.inputs.tracee = traceeSource
	engine.output = output
	engine.signatures = make(map[types.Signature]chan types.Event)
	engine.signaturesIndex = make(map[types.SignatureEventSelector][]types.Signature)
	for _, sig := range sigs {
		engine.signatures[sig] = make(chan types.Event)
		for _, es := range sig.GetSignatureEventSelectors() {
			if es.Name == "" {
				es.Name = "*"
			}
			engine.signaturesIndex[es] = append(engine.signaturesIndex[es], sig)
		}
		err := sig.Init(engine.matchHandler)
		if err != nil {
			log.Printf("error initializing signature %s: %v", sig.GetMetadata().Name, err)
		}
	}
	return engine
}

func (engine Engine) Start(done chan bool) {
	go engine.consumeSources()
	for s, c := range engine.signatures {
		go func(s types.Signature, c chan types.Event) {
			for {
				err := s.OnEvent(<-c)
				if err != nil {
					log.Printf("error handling event by signature %s: %v", s.GetMetadata().Name, err)
				}
			}
		}(s, c)
	}
	<-done
}

func (engine Engine) matchHandler(res types.Finding) {
	engine.output <- res
}

func (engine Engine) consumeSources() {
	for {
		select {
		case event, ok := <-engine.inputs.tracee:
			if !ok {
				for sig := range engine.signatures {
					for _, sel := range sig.GetSignatureEventSelectors() {
						if sel.Source == "tracee" {
							sig.OnSignal(types.SignalSourceComplete("tracee"))
							break
						}
					}
				}
				engine.inputs.tracee = nil
			} else if event != nil {
				for _, s := range engine.signaturesIndex[types.SignatureEventSelector{Source: "tracee", Name: event.(types.TraceeEvent).EventName}] {
					engine.signatures[s] <- event
				}
				for _, s := range engine.signaturesIndex[types.SignatureEventSelector{Source: "tracee", Name: "*"}] {
					engine.signatures[s] <- event
				}
			}
		}
	}
}
