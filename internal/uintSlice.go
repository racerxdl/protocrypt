package internal

import "sort"

// UIntSlice attaches the methods of Interface to []uint, sorting in increasing order.
type UIntSlice []uint

// Len returns the current length of UIntSlice
func (p UIntSlice) Len() int { return len(p) }

// Less returns if element i is less than element j
func (p UIntSlice) Less(i, j int) bool { return p[i] < p[j] }

// Swap swaps elements i and j
func (p UIntSlice) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

// Sort is a convenience method to sort the slice
func (p UIntSlice) Sort() { sort.Sort(p) }
