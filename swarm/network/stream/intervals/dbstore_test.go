// Copyright 2018 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
// This file is part of the github.com/blockchain-analysis-study/go-ethereum-analysis library.
//
// The github.com/blockchain-analysis-study/go-ethereum-analysis library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The github.com/blockchain-analysis-study/go-ethereum-analysis library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the github.com/blockchain-analysis-study/go-ethereum-analysis library. If not, see <http://www.gnu.org/licenses/>.

package intervals

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/swarm/state"
)

// TestDBStore tests basic functionality of DBStore.
func TestDBStore(t *testing.T) {
	dir, err := ioutil.TempDir("", "intervals_test_db_store")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	store, err := state.NewDBStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	testStore(t, store)
}
