// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package platform

import (
	"time"
)

const (

	// CNMRuntimePath is the path where CNM state files are stored.
	CNMRuntimePath = ""

	// CNIRuntimePath is the path where CNI state files are stored.
	CNIRuntimePath = ""

	// CNSRuntimePath is the path where CNS state files are stored.
	CNSRuntimePath = ""

	// NPMRuntimePath is the path where NPM state files are stored.
	NPMRuntimePath = ""

	// DNCRuntimePath is the path where DNC state files are stored.
	DNCRuntimePath = ""
)

// GetOSInfo returns OS version information.
func GetOSInfo() string {
	return "windows"
}

// GetLastRebootTime returns the last time the system rebooted.
func GetLastRebootTime() (time.Time, error) {
	var rebootTime time.Time
	return rebootTime, nil
}

func ExecuteCommand(command string) (string, error) {
	return "", nil
}

func SetOutboundSNAT(subnet string) error {
	return nil
}
