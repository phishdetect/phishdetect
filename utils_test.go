package phishdetect

import (
	"testing"
)

func TestTextContains(t *testing.T) {
	text := "This is A TEXT example"

	if !TextContains(text, "a text") {
		t.Errorf("Search for correct pattern failed, got false expected true")
	}

	if TextContains(text, "wrong") {
		t.Errorf("Search for incorrect pattern failed, got true expected false")
	}
}

func TestSliceContains(t *testing.T) {
	slice := []string{
		"first",
		"second",
		"third",
	}

	if !SliceContains(slice, "first") {
		t.Errorf("Search for correct slice element failed, got false expected true")
	}

	if SliceContains(slice, "wrong") {
		t.Errorf("Search for incorrect slice element failed, got true expected false")
	}
}

func TestNormalizeURL(t *testing.T) {
	url := "example.com"
	normalized := NormalizeURL(url)

	if normalized != "http://example.com" {
		t.Errorf("Normalizing URL scheme failed, expected \"http://example.com\" got \"%s\"", normalized)
	}

	url = "https://example.com"
	normalized = NormalizeURL(url)

	if normalized != url {
		t.Errorf("Normalizing correct URL filed, expected \"%s\" got \"%s\"", url, normalized)
	}
}
