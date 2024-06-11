package main

import (
	"context"
	"flag"
	"log"
	"strconv"
	"time"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}

	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout))

	serverPingInterval := osquery.ServerPingInterval(time.Second * time.Duration(*interval))

	server, err := osquery.NewExtensionManagerServer(
		"example_gpu_extension",
		*socket,
		serverTimeout,
		serverPingInterval)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(table.NewPlugin("example_gpu_usage_table", UsageColumns(), GenerateUsageTable))
	if err := server.Run(); err != nil {
		log.Fatalf("Error starting extension: %s\n", err)
	}
}

func UsageColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("device_id"),
		table.DoubleColumn("gpu_utilization"),
		table.DoubleColumn("gpu_memory_usage"),
	}
}

func GenerateUsageTable(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	usage := CollectUsageMetrics()
	if usage == nil {
		log.Fatalln("Unable to generate table see prior error messages")
	}

	var metrics []map[string]string
	for _, metric := range usage {
		x := map[string]string{
			"device_id":        metric.DeviceId,
			"gpu_utilization":  strconv.FormatFloat(metric.GPU, 'f', 2, 64),
			"gpu_memory_usage": strconv.FormatFloat(metric.Memory, 'f', 2, 64),
		}
		metrics = append(metrics, x)

	}
	return metrics, nil
}

type GPUUsage struct {
	DeviceId string
	GPU      float64
	Memory   float64
}

func CollectUsageMetrics() []GPUUsage {
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		log.Fatalf("Unable to initialize NVML: %v", nvml.ErrorString(ret))
	}

	defer func() {
		ret := nvml.Shutdown()
		if ret != nvml.SUCCESS {
			log.Fatalf("Unable to shutdown NVML: %v", nvml.ErrorString(ret))
		}
	}()

	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		log.Fatalf("Unable to get device count %v", nvml.ErrorString(ret))
	}

	var usages []GPUUsage
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			log.Fatalf("Unable to get device count: v%", nvml.ErrorString(ret))
		}

		deviceId, ret := device.GetUUID()
		if ret != nvml.SUCCESS {
			log.Fatalf("Unable to obtain device at index %d: %v", i, nvml.ErrorString(ret))
		}

		memory, ret := nvml.DeviceGetMemoryInfo(device)
		if ret != nvml.SUCCESS {
			log.Fatalf("Unable to get memory at %d: %v", i, nvml.ErrorString(ret))
		}

		use, ret := nvml.DeviceGetUtilizationRates(device)
		if ret != nvml.SUCCESS {
			log.Fatalf("Could not obtain Utilizaton Reate for %d: %v", i, nvml.ErrorString(ret))
		}

		usage := GPUUsage{
			DeviceId: deviceId,
			GPU:      float64(use.Gpu),
			Memory:   float64(memory.Used) / float64(memory.Total) * 100,
		}
		usages = append(usages, usage)

	}
	return usages
}
