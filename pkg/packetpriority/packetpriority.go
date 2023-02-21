package packetpriority

import (
	"fmt"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/qosmap"
	"github.com/cilium/cilium/pkg/option"
)

const (
	subsystem = "priority-manager"

	// EgressPriority is the K8s Pod annotation.
	EgressPriority = "network.cilium.io/packet-qos"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

var nameToValue = map[string]uint32{
	"low":    0,
	"top":    1,
}

func GetPriorityValue(priority string) (uint32, error) {
	val, ok := nameToValue[priority]
	if !ok {
		return 0, fmt.Errorf("unknown priority %q", priority)
	}
	return val, nil
}

func InitPriorityManager() {
	if option.Config.DryMode || !option.Config.EnablePriorityManager {
		return
	}

	if len(option.Config.GetDevices()) == 0 {
		log.Warn("BPF packet priority manager could not detect host devices. Disabling the feature.")
		option.Config.EnablePriorityManager = false
		return
	}

	log.Info("Setting up BPF priority manager")

	if _, err := qosmap.PriorityMap().OpenOrCreate(); err != nil {
		log.WithError(err).Fatal("Failed to access PriorityMap")
	}
}
