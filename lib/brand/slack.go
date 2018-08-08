package brand

// Slack brand properties.
func Slack() *Brand {
	name := "slack"
	original := []string{"slack"}
	whitelist := []string{"slack.com"}
	suspicious := []string{}

	return &Brand{
		Name:       name,
		Original:   original,
		Whitelist:  whitelist,
		Suspicious: suspicious,
	}
}
