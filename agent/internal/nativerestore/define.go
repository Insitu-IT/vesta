package nativerestore

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"os/exec"
	"time"

	"vnbui/agent/internal/backup"
	"vnbui/agent/internal/models"
)

//go:embed define.py
var defineProgram string

type DefinitionRequest struct {
	URI         string                      `json:"uri"`
	DomainXML   string                      `json:"domain_xml"`
	Manifest    models.NativePushManifest   `json:"manifest"`
	Target      models.NativeRestoreTarget  `json:"target"`
	Disks       []backup.NativeRestoredDisk `json:"disks"`
	RestoreID   string                      `json:"restore_id"`
	Token       string                      `json:"token"`
	PlanSHA256  string                      `json:"plan_sha256"`
	OutputPath  string                      `json:"output_path"`
	AllowCreate bool                        `json:"allow_create"`
}

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > 4<<20 {
		b.overflow = true
		return n, errors.New("native restore response exceeds control limit")
	}
	return b.Buffer.Write(p)
}

func Define(ctx context.Context, request DefinitionRequest) (map[string]interface{}, error) {
	body, err := json.Marshal(request)
	if err != nil || len(body) > 4<<20 {
		return nil, ErrBundle
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", defineProgram, "define")
	cmd.Stdin = bytes.NewReader(body)
	cmd.WaitDelay = 5 * time.Second
	var output boundedOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil || output.overflow {
		return nil, errors.New("restore held: native definition prerequisites, ownership or result require operator review")
	}
	var result map[string]interface{}
	if json.Unmarshal(output.Bytes(), &result) != nil {
		return nil, ErrBundle
	}
	return result, nil
}
