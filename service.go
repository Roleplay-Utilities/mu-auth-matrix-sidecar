package main

import (
	"fmt"
	"log"
	"os"

	"github.com/kardianos/service"
)

type program struct {
	exit chan struct{}
}

func (p *program) Start(s service.Service) error {
	p.exit = make(chan struct{})
	go p.run()
	return nil
}

func (p *program) run() {
	// 1. Run automatic update check asynchronously on startup
	go CheckForUpdates()

	// 2. Main application server loop
	fmt.Printf("Starting MU OIDC Sidecar (%s) as service...\n", Version)
	
	// TODO: Call your sidecar HTTP server initialization here
	// e.g., startServer()

	<-p.exit
}

func (p *program) Stop(s service.Service) error {
	close(p.exit)
	return nil
}

// SetupAndRunService configures systemd, Windows Service, or launchd automatically.
func SetupAndRunService() {
	svcConfig := &service.Config{
		Name:        "mu-sidecar",
		DisplayName: "MU OIDC Sidecar Service",
		Description: "MSC3861 OIDC sidecar bridge for Zendrite and MU Auth",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatalf("Failed to initialize service configuration: %v", err)
	}

	// If invoked with -install, -uninstall, or -service flags
	if len(os.Args) > 1 {
		action := os.Args[1]
		switch action {
		case "install":
			err = s.Install()
			if err != nil {
				log.Fatalf("Failed to install service: %v", err)
			}
			fmt.Println("Service installed successfully.")
			s.Start()
			return
		case "uninstall":
			s.Stop()
			err = s.Uninstall()
			if err != nil {
				log.Fatalf("Failed to uninstall service: %v", err)
			}
			fmt.Println("Service uninstalled successfully.")
			return
		}
	}

	// Auto-install service on first interactive boot if not already registered
	status, err := s.Status()
	if err == nil && status == service.StatusUnknown {
		_ = s.Install()
	}

	// Run process under OS Service Manager or fallback to standard Interactive Terminal
	if err := s.Run(); err != nil {
		log.Printf("Service run error: %v", err)
	}
}