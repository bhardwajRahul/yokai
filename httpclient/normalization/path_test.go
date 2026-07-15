package normalization_test

import (
	"testing"

	"github.com/ankorstore/yokai/httpclient/normalization"
)

func TestMask(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		masks map[string]string
		path  string
		want  string
	}{
		"primary mask applied": {
			map[string]string{
				`/foo/(.+)/bar\?page=(.+)#baz`: "/foo/{fooId}/bar?page={pageId}#baz",
			},
			"/foo/1/bar?page=1#baz",
			"/foo/{fooId}/bar?page={pageId}#baz",
		},
		"secondary mask applied": {
			map[string]string{
				`/foo/(.+)/baz\?page=(.+)#baz`: "/foo/{fooId}/baz?page={pageId}#baz",
				`/foo/(.+)/bar\?page=(.+)#baz`: "/foo/{fooId}/bar?page={pageId}#baz",
			},
			"/foo/1/bar?page=1#baz",
			"/foo/{fooId}/bar?page={pageId}#baz",
		},
		// No mask matches: the path is sanitized (query dropped, id segment masked)
		// instead of being returned raw.
		"primary mask not applied falls back to sanitized path": {
			map[string]string{
				`/foo/(.+)/bar\?page=(.+)#baz`: "/foo/{fooId}/bar?page={pageId}#baz",
			},
			"/foo/1/bar?pages=1#baz",
			"/foo/{id}/bar",
		},
		"invalid regexp mask falls back to sanitized path": {
			map[string]string{
				`(.`: "/foo/{fooId}/bar?page={pageId}#baz",
			},
			"/foo/1/bar?page=1#baz",
			"/foo/{id}/bar",
		},
		"empty masks list falls back to sanitized path": {
			map[string]string{},
			"/foo/1/bar?page=1#baz",
			"/foo/{id}/bar",
		},
	}

	for name, tt := range tests {
		got := normalization.NormalizePath(tt.masks, tt.path)
		if got != tt.want {
			t.Errorf("%s: expected %s, got %s", name, tt.want, got)
		}
	}
}

func TestSanitizePath(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path string
		want string
	}{
		"query string dropped": {
			"/search?q=some-value&page=2",
			"/search",
		},
		"query dropped and mixed id segment masked": {
			"/orders/abc-123?page=2",
			"/orders/{id}",
		},
		"numeric segment masked": {
			"/users/42",
			"/users/{id}",
		},
		"uuid segment masked": {
			"/orders/123e4567-e89b-12d3-a456-426614174000",
			"/orders/{id}",
		},
		"long hex segment masked": {
			"/blobs/deadbeefdeadbeef00",
			"/blobs/{id}",
		},
		"multiple id segments masked": {
			"/a/1/b/2",
			"/a/{id}/b/{id}",
		},
		"static segments left untouched": {
			"/v1/payment-methods/oauth2",
			"/v1/payment-methods/oauth2",
		},
		"short digit in segment left untouched": {
			"/enc/utf-8",
			"/enc/utf-8",
		},
		"path without id or query unchanged": {
			"/health",
			"/health",
		},
		"root path unchanged": {
			"/",
			"/",
		},
		"empty path unchanged": {
			"",
			"",
		},
	}

	for name, tt := range tests {
		got := normalization.SanitizePath(tt.path)
		if got != tt.want {
			t.Errorf("%s: expected %q, got %q", name, tt.want, got)
		}
	}
}
