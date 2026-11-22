package util

import (
	"errors"
	"regexp"
)

var newUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9]{6,20}$`)

// MaskTrafficRankName hides a leaderboard name without slicing short or
// multi-byte names. Existing short names stay in the database unchanged.
func MaskTrafficRankName(name string) string {
	chars := []rune(name)
	switch len(chars) {
	case 0:
		return "****"
	case 1:
		return string(chars) + "****"
	default:
		return string(chars[:2]) + "****" + string(chars[len(chars)-2:])
	}
}

// SameOrValidUsername accepts an unchanged name, including one that is already
// shorter than the current rule. A replacement must be 6 to 20 letters or digits.
func SameOrValidUsername(current, next string) error {
	if next == current {
		return nil
	}
	if !newUsernamePattern.MatchString(next) {
		return errors.New("用户名需为6到20位字母或数字")
	}
	return nil
}

// FinishRemoteThenLocal runs the local change only after the remote call succeeds.
func FinishRemoteThenLocal(remote, local func() error) error {
	if remote == nil || local == nil {
		return errors.New("missing delete step")
	}
	if err := remote(); err != nil {
		return err
	}
	return local()
}
