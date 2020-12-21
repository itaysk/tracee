package main

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func setupStdinSource() (chan types.Event, error) {
	res := make(chan types.Event)
	scanner := bufio.NewScanner(os.Stdin)
	go func() {
		for scanner.Scan() {
			res <- types.TraceeEvent{
				ArgsNum: 1,
				Args: []types.TraceeEventArgument{
					{
						Name:  "pathname",
						Value: scanner.Text(),
					},
				},
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
				fmt.Println(event)
				res <- event
			}
		}
		f.Close()
		close(res)
	}()
	return res, nil
}
