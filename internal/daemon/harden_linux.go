package daemon

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Hardening reports the process setting and the limit for best-effort locks
// on the actual key/value buffers owned by vault and grants.
type Hardening struct {
	Dumpable                 int
	MemlockSoft, MemlockHard uint64
}

// Harden must run in the production process before handling credentials.
// It never applies mlockall; individual secret buffers attempt their own lock.
func Harden() (Hardening, error) {
	var report Hardening
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return report, err
	}
	n, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return report, err
	}
	report.Dumpable = n
	if n != 0 {
		return report, errors.New("daemon: dumpability remains enabled")
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return report, err
	}
	report.MemlockSoft, report.MemlockHard = limit.Cur, limit.Max
	return report, nil
}
