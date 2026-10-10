//go:build !linux

package alerts

import "errors"

// Sampler is unavailable outside Linux.
type Sampler struct{}

// Sample is unsupported here.
func (s *Sampler) Sample(string) (Metrics, error) {
	return Metrics{}, errors.New("metrics need Linux /proc")
}
