package phishdetect

import (
	"time"
)

// BrowserWaitTime is the seconds we will wait before fetching navigation results.
const BrowserWaitTime time.Duration = 5

// BrowserTimeout is the minutes we will wait before declaring failed the
// connection to our debugged browser or to the URL failed.
const BrowserTimeout time.Duration = 1
