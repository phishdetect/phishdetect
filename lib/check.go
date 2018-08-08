package phishdetect

// CheckFunction defines the functions used to implement URL or HTML checks.
type CheckFunction func(*Link, *Page, *Brands) bool

// Check defines the general proprties of a CheckFunction.
type Check struct {
	Call        CheckFunction
	Score       int
	Name        string
	Description string
}
