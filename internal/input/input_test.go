package input

import (
	"strings"
	"testing"
)

func TestReadLinesSkipsBlanksAndComments(t *testing.T) {
	in := "example.com\n\n# comment\nhttps://x.com\n   \n"
	got, err := readLines(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "https://x.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadCSVHeaderColumn(t *testing.T) {
	in := "name,url,note\nAcme,acme.com,x\nBeta,https://beta.io,y\n"
	got, err := readCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"acme.com", "https://beta.io"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestReadCSVNoHeaderUsesFirstColumn(t *testing.T) {
	in := "acme.com,x\nbeta.io,y\n"
	got, err := readCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "acme.com" || got[1] != "beta.io" {
		t.Fatalf("got %v, want [acme.com beta.io]", got)
	}
}
