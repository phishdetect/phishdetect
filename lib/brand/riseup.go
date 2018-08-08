package brand

// RiseUp brand properties.
func RiseUp() *Brand {
	name := "riseup"
	original := []string{"riseup"}
	whitelist := []string{"riseup.net"}
	suspicious := []string{}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
