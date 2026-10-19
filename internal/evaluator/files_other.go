//go:build !unix

package evaluator

import "errors"

func readProtected(string, int, bool, bool) ([]byte, error) {
	return nil, errors.New("decision configuration currently requires Unix file ownership checks")
}
