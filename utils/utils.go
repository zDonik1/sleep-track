package utils

func Map[Slice []E, E, R any](s Slice, f func(E) R) []R {
	var result []R = make([]R, len(s))
	for i, e := range s {
		result[i] = f(e)
	}
	return result
}
