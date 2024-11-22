package main

import (
	"syscall"
)

func (s *Server) getProcessAttr() *syscall.SysProcAttr {
	// Return empty process attributes that work across platforms
	return &syscall.SysProcAttr{}
}
