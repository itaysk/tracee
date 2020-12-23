package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/tracee/tracee-rules/engine"
	"github.com/aquasecurity/tracee/tracee-rules/types"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "tracee-rules",
		Usage: "A rule engine for Runtime Security",
		Action: func(c *cli.Context) error {
			sigs, err := getSignatures(c.String("rules-dir"), c.StringSlice("rules"))
			if err != nil {
				return err
			}
			var inputTracee chan types.Event
			if c.IsSet("tracee-file") {
				inputTracee, err = setupTraceeSource(c.String("tracee-file"))
			}
			if c.IsSet("stdin-as") {
				inputTracee, err = setupStdinSource(c.String("stdin-as"))
			}
			if err != nil || inputTracee == nil {
				return err
			}
			output, err := setupOuput(c.String("webhook"))
			if err != nil {
				return err
			}
			e := engine.NewEngine(sigs, inputTracee, output)
			e.Start(sigHandler())
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "rules",
				Usage: "select which rules to load",
			},
			&cli.StringFlag{
				Name:  "rules-dir",
				Usage: "directory where to search for rules",
			},
			&cli.StringFlag{
				Name:  "webhook",
				Usage: "call this HTTP endpoint for every match",
			},
			&cli.StringFlag{
				Name:  "tracee-file",
				Usage: "path to Tracee Gob output file",
			},
			&cli.StringFlag{
				Name:  "stdin-as",
				Usage: "read events from stdin and treat them as JSON serielizer events of the specified input source. this will override an already configured input source",
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func sigHandler() chan bool {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()
	return done
}
