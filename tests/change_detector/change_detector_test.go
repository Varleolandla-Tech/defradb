// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package change_detector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChanges(t *testing.T) {
	sourceRepoDir := t.TempDir()
	execClone(t, sourceRepoDir, repository, sourceBranch)

	if checkIfDatabaseFormatChangesAreDocumented(t, sourceRepoDir) {
		t.Skip("skipping test with documented database format changes")
	}

	targetRepoDir := t.TempDir()
	execClone(t, targetRepoDir, repository, targetBranch)

	execMakeDeps(t, sourceRepoDir)
	execMakeDeps(t, targetRepoDir)

	targetRepoTestDir := filepath.Join(targetRepoDir, "tests", "integration")
	targetRepoPkgList := execList(t, targetRepoTestDir)

	sourceRepoTestDir := filepath.Join(sourceRepoDir, "tests", "integration")
	sourceRepoPkgList := execList(t, sourceRepoTestDir)

	sourceRepoPkgMap := make(map[string]bool)
	for _, pkg := range sourceRepoPkgList {
		sourceRepoPkgMap[pkg] = true
	}

	for _, pkg := range targetRepoPkgList {
		pkgName := strings.TrimPrefix(pkg, "github.com/sourcenetwork/defradb/")
		t.Run(pkgName, func(t *testing.T) {
			if pkg == "" || !sourceRepoPkgMap[pkg] {
				t.Skip("skipping unknown or new test package")
			}

			t.Parallel()
			dataDir := t.TempDir()

			sourceTestPkg := filepath.Join(sourceRepoDir, pkgName)
			execTest(t, sourceTestPkg, dataDir, true)

			targetTestPkg := filepath.Join(targetRepoDir, pkgName)
			execTest(t, targetTestPkg, dataDir, false)
		})
	}
}

// execList returns a list of all packages in the given directory.
func execList(t *testing.T, dir string) []string {
	cmd := exec.Command("go", "list", "./...")
	cmd.Dir = dir

	out, err := cmd.Output()
	require.NoError(t, err, string(out))

	return strings.Split(string(out), "\n")
}

// execTest runs the tests in the given directory and sets the data
// directory and setup only environment variables.
func execTest(t *testing.T, dir, dataDir string, setupOnly bool) {
	cmd := exec.Command("go", "test", ".", "-count", "1", "-v")
	cmd.Dir = dir
	cmd.Env = append(
		os.Environ(),
		fmt.Sprintf("%s=%s", enableEnvName, "true"),
		fmt.Sprintf("%s=%s", rootDataDirEnvName, dataDir),
	)

	if setupOnly {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", setupOnlyEnvName, "true"))
	}

	out, err := cmd.Output()
	require.NoError(t, err, string(out))
}

// execClone clones the repo from the given url and branch into the directory.
func execClone(t *testing.T, dir, url, branch string) {
	cmd := exec.Command(
		"git",
		"clone",
		"--single-branch",
		"--branch", branch,
		"--depth", "1",
		url,
		dir,
	)

	out, err := cmd.Output()
	require.NoError(t, err, string(out))
}

// execMakeDeps runs make:deps in the given directory.
func execMakeDeps(t *testing.T, dir string) {
	cmd := exec.Command("make", "deps:lens")
	cmd.Dir = dir

	out, err := cmd.Output()
	require.NoError(t, err, string(out))
}
