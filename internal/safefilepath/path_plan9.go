// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safefilepath

import "github.com/SamuelLorentz/shttp/internal/bytealg"

func localize(path string) (string, error) {
	if path[0] == '#' || bytealg.IndexByteString(path, 0) >= 0 {
		return "", errInvalidPath
	}
	return path, nil
}
