// Package banner provides simple banner grab and matching implementation of the zgrab2.Module.
// It sends a customizble probe (default to "\n") and filters the results based on custom regexp (--pattern)

package banner

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strconv"

	log2 "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	Probe     string `long:"probe" default:"\\n" description:"Probe to send to the server. Use triple slashes to escape, for example \\\\\\n is literal \\n" `
	ProbeFile string `long:"probe-file" description:"File to get probe from."`
	Pattern   string `long:"pattern" description:"Pattern to match, must be valid regexp."`
	MaxTries  int    `long:"max-tries" default:"1" description:"Number of tries for timeouts and connection errors before giving up."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	regex  *regexp.Regexp
	probe  []byte
}

type Results struct {
	Banner string `json:"banner,omitempty"`
	Length int    `json:"length,omitempty"`
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("banner", "Banner", module.Description(), 80, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "banner"
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	return nil
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Fetch a raw banner by sending a static probe and checking the result against a regular expression"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.regex = regexp.MustCompile(scanner.config.Pattern)
	if len(scanner.config.ProbeFile) > 0 {
		probe, err := ioutil.ReadFile(scanner.config.ProbeFile)
		if err != nil {
			panic("Can't open Probe File")
		}
		scanner.config.Probe = string(probe)
	}
	probe, err := strconv.Unquote(fmt.Sprintf(`"%s"`, scanner.config.Probe))
	if err != nil {
		panic("Probe error")
	}
	scanner.probe = []byte(probe)
	log2.Infof("probe: % x\n", scanner.probe)
	return nil
}

var NoMatchError = errors.New("pattern did not match")

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	try := 0
	var (
		conn    net.Conn
		err     error
		readerr error
	)
	for try < scanner.config.MaxTries {
		try += 1
		conn, err = target.Open(&scanner.config.BaseFlags)
		if err != nil {
			continue
		}
		break
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	var ret []byte
	var newRet []byte
	try = 0
	_, err = conn.Write(scanner.probe)
	for {
		try++
		newRet, readerr = zgrab2.ReadAvailable(conn)
		if len(newRet) > 0 {
			log2.Infof("ip: %s response: % x", target.Host(), newRet)
		}
		ret = append(ret, newRet...)
		if readerr == io.EOF {
			log.Printf("ip: %s readerr: %v", target.Host(), readerr)
			break
		} else if readerr != nil {
			errStr := readerr.Error()
			if errStr[len(errStr)-11:] == "i/o timeout" {
				break
			}
			continue
		}
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if readerr != io.EOF && readerr != nil {
		errStr := readerr.Error()
		if errStr[len(errStr)-11:] != "i/o timeout" {
			return zgrab2.TryGetScanStatus(readerr), nil, readerr
		}
	}
	results := Results{Banner: string(ret), Length: len(ret)}
	if scanner.regex.Match(ret) {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, &results, NoMatchError

}
