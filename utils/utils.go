package utils

func Map[Slice []E, E, R any](s Slice, f func(E) R) []R {
	result := make([]R, len(s))
	for i, e := range s {
		result[i] = f(e)
	}
	return result
}
