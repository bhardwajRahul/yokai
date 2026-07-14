package normalization

import (
	"regexp"
	"strings"
)

// idPlaceholder is the value substituted for identifier-like path segments.
const idPlaceholder = "{id}"

var (
	// uuidRegexp matches a canonical UUID path segment.
	uuidRegexp = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// numericRegexp matches a path segment made only of digits (e.g. "42").
	numericRegexp = regexp.MustCompile(`^\d+$`)
	// longHexRegexp matches long hex segments such as SHA hashes or Mongo ObjectIDs.
	longHexRegexp = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	// digitRunRegexp matches any segment containing a run of 3+ digits, which
	// catches mixed identifiers like "abc-123" or "order-4567" while leaving
	// version-like segments ("v1", "oauth2", "utf-8") untouched.
	digitRunRegexp = regexp.MustCompile(`\d{3,}`)
)

// NormalizePath normalizes a path to keep the resulting metric label low-cardinality.
//
// If the path matches one of the provided masks, the mask is returned (masks take
// priority and let callers produce human-friendly labels, e.g.
// NormalizePath(map[string]string{"/foo/(.+)": "/foo/{id}"}, "/foo/1") returns "/foo/{id}").
//
// If no mask matches, the path is sanitized via [SanitizePath] instead of being
// returned as-is. This is a fail-safe default: an un-masked path carrying dynamic
// identifiers (or a query string) no longer leaks unbounded label values, which
// would otherwise cause metric cardinality explosions.
func NormalizePath(masks map[string]string, path string) string {
	for pattern, mask := range masks {
		re, err := regexp.Compile(pattern)
		if err == nil {
			matched := re.MatchString(path)
			if matched {
				return mask
			}
		}
	}

	return SanitizePath(path)
}

// SanitizePath returns a low-cardinality version of a request path by:
//   - dropping the query string and fragment (everything from '?' or '#' onward), and
//   - replacing identifier-like segments (UUIDs, all-digit, long hex, or any segment
//     containing a run of 3+ digits) with the "{id}" placeholder.
//
// Segments that look like static route parts (e.g. "v1", "oauth2", "payment-methods")
// are left unchanged. It is conservative on purpose to avoid masking legitimate routes.
func SanitizePath(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}

	if path == "" {
		return path
	}

	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment == "" {
			continue
		}

		if isIdentifierSegment(segment) {
			segments[i] = idPlaceholder
		}
	}

	return strings.Join(segments, "/")
}

// isIdentifierSegment reports whether a path segment looks like a dynamic identifier.
func isIdentifierSegment(segment string) bool {
	return numericRegexp.MatchString(segment) ||
		uuidRegexp.MatchString(segment) ||
		longHexRegexp.MatchString(segment) ||
		digitRunRegexp.MatchString(segment)
}
