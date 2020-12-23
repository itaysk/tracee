package main

import (
	"bufio"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func setupStdinSource(inputSource string) (chan types.Event, error) {
	res := make(chan types.Event)
	scanner := bufio.NewScanner(os.Stdin)
	go func() {
		for scanner.Scan() {
			event := scanner.Bytes()
			switch inputSource {
			case "tracee":
				var e types.TraceeEvent
				err := json.Unmarshal(event, &e)
				if err != nil {
					log.Printf("invalid json in %s: %v", string(event), err)
				}
				res <- types.Event(e)
			}
		}
		close(res)
	}()
	return res, nil
}

func setupTraceeSource(traceeFilePath string) (chan types.Event, error) {
	f, err := os.Open(traceeFilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file: %s", traceeFilePath)
	}
	dec := gob.NewDecoder(f)
	res := make(chan types.Event)
	go func() {
		for {
			var event types.TraceeEvent
			err := dec.Decode(&event)
			if err != nil {
				if err == io.EOF {
					break
				} else {
					log.Printf("Error while decoding event: %v", err)
				}
			} else {
				res <- event
			}
		}
		f.Close()
		close(res)
	}()
	return res, nil
}
