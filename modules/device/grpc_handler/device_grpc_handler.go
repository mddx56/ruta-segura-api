package grpc_handler

import (
	"context"

	"github.com/Caknoooo/go-gin-clean-starter/modules/device/service"
	pb "github.com/Caknoooo/go-gin-clean-starter/pkg/pb/device_proto"
)

type DeviceGRPCHandler struct {
	pb.UnimplementedDeviceServiceServer
	deviceService service.DeviceService
}

func NewDeviceGRPCHandler(s service.DeviceService) *DeviceGRPCHandler {
	return &DeviceGRPCHandler{deviceService: s}
}

func (h *DeviceGRPCHandler) ListDevicesSimple(ctx context.Context, req *pb.ListDevicesRequest) (*pb.ListDevicesResponse, error) {
	devices, err := h.deviceService.FindAll(ctx)
	if err != nil {
		return nil, err
	}

	var pbDevices []*pb.DeviceItem
	for _, dev := range devices {
		simPhone := ""
		if dev.SimPhoneNumber != nil {
			simPhone = *dev.SimPhoneNumber
		}
		pbDevices = append(pbDevices, &pb.DeviceItem{
			Imei:           dev.IMEI,
			Model:          dev.Model,
			SimPhoneNumber: simPhone,
			Status:         dev.Status,
		})
	}

	return &pb.ListDevicesResponse{Devices: pbDevices}, nil
}
