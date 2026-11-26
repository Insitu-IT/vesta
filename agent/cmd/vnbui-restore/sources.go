package main

import "vnbui/agent/internal/restoreinput"

type s3Configuration = restoreinput.S3Configuration

var localSource = restoreinput.LocalSource
var s3Source = restoreinput.S3Source
var fileKeys = restoreinput.FileKeys
