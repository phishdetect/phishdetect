package brand

// Brand defines the attributes of a brand.
type Brand struct {
	Name       string
	Original   []string
	Whitelist  []string
	Suspicious []string
	Matches    int
}
