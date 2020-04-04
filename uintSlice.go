package protocrypt

import "sort"

// UIntSlice attaches the methods of Interface to []int, sorting in increasing order.
type UIntSlice []uint

func (p UIntSlice) Len() int           { return len(p) }
func (p UIntSlice) Less(i, j int) bool { return p[i] < p[j] }
func (p UIntSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// Sort is a convenience method.
func (p UIntSlice) Sort() { sort.Sort(p) }
