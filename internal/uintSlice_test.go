package internal

import (
	"math/rand"
	"testing"
)

func TestUIntSlice_Len(t *testing.T) {
	n := rand.Intn(64)

	testSlice := UIntSlice(make([]uint, n))

	if testSlice.Len() != n {
		t.Errorf("Expected length to be %d got %d", n, testSlice.Len())
	}
}

func TestUIntSlice_Sort(t *testing.T) {
	unsortedSlice := UIntSlice{0, 5, 6, 2, 1, 9, 4, 2, 3, 20, 40, 32}
	unsortedSlice.Sort()

	for i, v := range unsortedSlice {
		if i > 0 {
			if unsortedSlice[i-1] > v {
				t.Errorf("Slice is not sorted. Expected slice[%d] <= slice[%d]", i-1, i)
			}
		}
	}
}

func TestUIntSlice_Swap(t *testing.T) {
	unsortedSlice := UIntSlice{0, 5, 8}
	unsortedSlice.Swap(1, 2)

	if unsortedSlice[1] != 8 || unsortedSlice[2] != 5 {
		t.Errorf("Expected positions 1 and 2 to be swapped")
	}
}

func TestUIntSlice_Less(t *testing.T) {
	unsortedSlice := UIntSlice{0, 5}

	if !unsortedSlice.Less(0, 1) {
		t.Errorf("Expected %d to be less %d", unsortedSlice[0], unsortedSlice[1])
	}
	if unsortedSlice.Less(1, 0) {
		t.Errorf("Expected %d not to be less %d", unsortedSlice[1], unsortedSlice[0])
	}
}
