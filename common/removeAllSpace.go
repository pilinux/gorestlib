package common

// github.com/pilinux/gorestlib
// The MIT License (MIT)
// Copyright (c) 2022 pilinux

import "strings"

// RemoveAllSpace - remove all spaces and return
// the result as string
func RemoveAllSpace(s string) string {
	return strings.ReplaceAll(s, " ", "")
}
