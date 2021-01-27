// Copyright 2017 The github.com/blockchain-analysis-study/go-ethereum-analysis Authors
// This file is part of github.com/blockchain-analysis-study/go-ethereum-analysis.
//
// github.com/blockchain-analysis-study/go-ethereum-analysis is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// github.com/blockchain-analysis-study/go-ethereum-analysis is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with github.com/blockchain-analysis-study/go-ethereum-analysis. If not, see <http://www.gnu.org/licenses/>.

package compiler

import (
	"errors"
	"fmt"

	"github.com/blockchain-analysis-study/go-ethereum-analysis/core/asm"
)

func Compile(fn string, src []byte, debug bool) (string, error) {
	compiler := asm.NewCompiler(debug)
	compiler.Feed(asm.Lex(fn, src, debug))

	bin, compileErrors := compiler.Compile()
	if len(compileErrors) > 0 {
		// report errors
		for _, err := range compileErrors {
			fmt.Printf("%s:%v\n", fn, err)
		}
		return "", errors.New("compiling failed")
	}
	return bin, nil
}
