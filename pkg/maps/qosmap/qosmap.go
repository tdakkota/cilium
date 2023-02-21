// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package qosmap

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
)

const (
	MapName = "cilium_priority"
	// Flow aggregate is per Pod, so same size as Endpoint map.
	MapSize = lxcmap.MaxEntries
)

type EptId struct {
	Id uint64 `align:"id"`
}

func (k *EptId) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(k) }
func (k *EptId) NewValue() bpf.MapValue     { return &EptInfo{} }
func (k *EptId) String() string             { return fmt.Sprintf("%d", int(k.Id)) }
func (k *EptId) DeepCopyMapKey() bpf.MapKey { return &EptId{k.Id} }

type EptInfo struct {
	Priority uint32
	Pad      [1]uint32 `align:"pad"`
}

func (v *EptInfo) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }
func (v *EptInfo) String() string              { return fmt.Sprintf("%d", int(v.Priority)) }
func (v *EptInfo) DeepCopyMapValue() bpf.MapValue {
	return &EptInfo{Priority: v.Priority, Pad: v.Pad}
}

var (
	priorityMap     *bpf.Map
	priorityMapInit = &sync.Once{}
)

func PriorityMap() *bpf.Map {
	priorityMapInit.Do(func() {
		priorityMap = bpf.NewMap(
			MapName,
			bpf.MapTypeHash,
			&EptId{}, int(unsafe.Sizeof(EptId{})),
			&EptInfo{}, int(unsafe.Sizeof(EptInfo{})),
			MapSize,
			bpf.BPF_F_NO_PREALLOC, 0,
			bpf.ConvertKeyValue,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapName))
	})

	return priorityMap
}

func Update(Id uint16, Priority uint32) error {
	return PriorityMap().Update(
		&EptId{Id: uint64(Id)},
		&EptInfo{Priority: Priority})
}

func Delete(Id uint16) error {
	return PriorityMap().Delete(
		&EptId{Id: uint64(Id)})
}

func SilentDelete(Id uint16) error {
	_, err := PriorityMap().SilentDelete(
		&EptId{Id: uint64(Id)})

	return err
}
