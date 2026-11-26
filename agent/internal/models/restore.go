package models

// RestoreRequest is a request to execute a restore.
// JSON tags must match Python RestoreRequest field names exactly.
type RestoreRequest struct {
	RestoreID         string                   `json:"restore_id"`
	BackupPath        string                   `json:"backup_path"`
	RestorePath       string                   `json:"restore_path"`
	Action            string                   `json:"action"`
	SelectedDisks     []string                 `json:"selected_disks"`
	TargetName        *string                  `json:"target_name"`
	UntilCheckpoint   *string                  `json:"until_checkpoint"`
	AutoDefine        bool                     `json:"auto_define"`
	AdjustConfig      bool                     `json:"adjust_config"`
	EncryptionType    *EncryptionType          `json:"encryption_type"`
	EncryptionKey     *string                  `json:"encryption_key"`
	EncryptionKeyHash *string                  `json:"encryption_key_hash"`
	Source            string                   `json:"source"`
	S3Config          map[string]interface{}   `json:"s3_config"`
	ChainMembers      []map[string]interface{} `json:"chain_members"`
	KubeVirt          *KubeVirtRestoreRequest  `json:"kubevirt,omitempty"`
	Native            *NativeRestoreRequest    `json:"native,omitempty"`
}

// RestoreProgress is restore progress information.
// JSON tags must match Python RestoreProgress field names exactly.
type RestoreProgress struct {
	RestoreID        string                 `json:"restore_id"`
	Status           TaskStatus             `json:"status"`
	ProgressPercent  int                    `json:"progress_percent"`
	CurrentOperation *string                `json:"current_operation"`
	ErrorMessage     *string                `json:"error_message"`
	Result           map[string]interface{} `json:"result,omitempty"`
}
