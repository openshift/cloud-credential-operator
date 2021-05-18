package utils

import (
	"regexp"
)

var (
	awsRequestIDRE = regexp.MustCompile(`(, )*(request id|Request ID): ([-0-9a-f]+)`)
	newlineTabRE   = regexp.MustCompile(`(\n\t)`)
)

// ErrorScrub scrubs cloud error messages destined for CRD status to remove things that
// change every attempt, such as request IDs, which subsequently cause an infinite update/reconcile loop.
func ErrorScrub(err error) string {
	s := awsRequestIDRE.ReplaceAllString(err.Error(), "")
	s = newlineTabRE.ReplaceAllString(s, ", ")
	return s
}
