// Command checkblockinglocks rejects blocking queue, channel, wait, and socket
// operations performed while a state or lifecycle mutex is held.
//
// It intentionally complements checklocks: checklocks verifies protected data,
// while this command verifies the package's shutdown/liveness lock discipline.
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type lockSet map[string]int

func (s lockSet) clone() lockSet {
	copy := make(lockSet, len(s))
	for name, count := range s {
		copy[name] = count
	}
	return copy
}

func mergeLocks(sets ...lockSet) lockSet {
	merged := make(lockSet)
	for _, set := range sets {
		for name, count := range set {
			if count > merged[name] {
				merged[name] = count
			}
		}
	}
	return merged
}

type analyzer struct {
	fset        *token.FileSet
	diagnostics []string
}

func (a *analyzer) report(node ast.Node, held lockSet, operation string) {
	locks := make([]string, 0, len(held))
	for name, count := range held {
		if count > 0 {
			locks = append(locks, name)
		}
	}
	if len(locks) == 0 {
		return
	}
	a.diagnostics = append(a.diagnostics, fmt.Sprintf(
		"%s: blocking %s while lifecycle/state lock(s) %s are held",
		a.fset.Position(node.Pos()), operation, strings.Join(locks, ", "),
	))
}

func exprString(fset *token.FileSet, expr ast.Expr) string {
	var out bytes.Buffer
	if err := format.Node(&out, fset, expr); err != nil {
		return "<unknown>"
	}
	return out.String()
}

func lockName(fset *token.FileSet, call *ast.CallExpr) (name, action string, ok bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (selector.Sel.Name != "Lock" && selector.Sel.Name != "Unlock") {
		return "", "", false
	}

	var field string
	switch receiver := selector.X.(type) {
	case *ast.Ident:
		field = receiver.Name
	case *ast.SelectorExpr:
		field = receiver.Sel.Name
	}
	if field != "l" && field != "m" && field != "lifecycleMu" {
		return "", "", false
	}
	return exprString(fset, selector.X), selector.Sel.Name, true
}

func directLockOperation(fset *token.FileSet, statement ast.Stmt) (name, action string, ok bool) {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return "", "", false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok {
		return "", "", false
	}
	return lockName(fset, call)
}

func (a *analyzer) checkBlockingExpressions(node ast.Node, held lockSet) {
	ast.Inspect(node, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.FuncLit:
			// A closure has its own execution context. Analyze its lock state from
			// scratch rather than inheriting locks held while it is created.
			a.checkBlock(value.Body.List, make(lockSet))
			return false
		case *ast.UnaryExpr:
			if value.Op == token.ARROW {
				a.report(value, held, "channel receive")
			}
		case *ast.CallExpr:
			selector, ok := value.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver := exprString(a.fset, selector.X)
			switch selector.Sel.Name {
			case "Send", "Recv", "RecvQueued", "Wait", "WaitForClose", "enqueue":
				a.report(value, held, selector.Sel.Name+" call")
			case "Read", "ReadMsg", "ReadMsgUDP", "Write", "WriteMsg", "WriteMsgUDP", "Close":
				if strings.Contains(receiver, "underlying") || strings.Contains(receiver, "udpConn") {
					a.report(value, held, selector.Sel.Name+" on "+receiver)
				}
			}
		}
		return true
	})
}

func selectHasDefault(statement *ast.SelectStmt) bool {
	for _, item := range statement.Body.List {
		clause := item.(*ast.CommClause)
		if clause.Comm == nil {
			return true
		}
	}
	return false
}

func (a *analyzer) checkBlock(statements []ast.Stmt, held lockSet) lockSet {
	current := held.clone()
	for _, statement := range statements {
		if name, action, ok := directLockOperation(a.fset, statement); ok {
			switch action {
			case "Lock":
				current[name]++
			case "Unlock":
				if current[name] > 0 {
					current[name]--
				}
			}
			continue
		}

		switch value := statement.(type) {
		case *ast.BlockStmt:
			current = a.checkBlock(value.List, current)
		case *ast.IfStmt:
			base := current.clone()
			if value.Init != nil {
				base = a.checkBlock([]ast.Stmt{value.Init}, base)
			}
			a.checkBlockingExpressions(value.Cond, base)
			branches := []lockSet{a.checkBlock(value.Body.List, base)}
			if value.Else == nil {
				branches = append(branches, base)
			} else {
				branches = append(branches, a.checkBlock([]ast.Stmt{value.Else}, base))
			}
			current = mergeLocks(branches...)
		case *ast.ForStmt:
			loop := current.clone()
			if value.Init != nil {
				loop = a.checkBlock([]ast.Stmt{value.Init}, loop)
			}
			if value.Cond != nil {
				a.checkBlockingExpressions(value.Cond, loop)
			}
			a.checkBlock(value.Body.List, loop)
			if value.Post != nil {
				a.checkBlock([]ast.Stmt{value.Post}, loop)
			}
		case *ast.RangeStmt:
			a.checkBlockingExpressions(value.X, current)
			a.checkBlock(value.Body.List, current)
		case *ast.SelectStmt:
			if !selectHasDefault(value) {
				a.report(value, current, "select")
			}
			branches := make([]lockSet, 0, len(value.Body.List))
			for _, item := range value.Body.List {
				clause := item.(*ast.CommClause)
				branches = append(branches, a.checkBlock(clause.Body, current))
			}
			if len(branches) > 0 {
				current = mergeLocks(branches...)
			}
		case *ast.SwitchStmt:
			base := current.clone()
			if value.Init != nil {
				base = a.checkBlock([]ast.Stmt{value.Init}, base)
			}
			if value.Tag != nil {
				a.checkBlockingExpressions(value.Tag, base)
			}
			branches := make([]lockSet, 1, 1+len(value.Body.List))
			branches[0] = base
			for _, item := range value.Body.List {
				clause := item.(*ast.CaseClause)
				branches = append(branches, a.checkBlock(clause.Body, base))
			}
			current = mergeLocks(branches...)
		case *ast.TypeSwitchStmt:
			base := current.clone()
			if value.Init != nil {
				base = a.checkBlock([]ast.Stmt{value.Init}, base)
			}
			branches := make([]lockSet, 1, 1+len(value.Body.List))
			branches[0] = base
			for _, item := range value.Body.List {
				clause := item.(*ast.CaseClause)
				branches = append(branches, a.checkBlock(clause.Body, base))
			}
			current = mergeLocks(branches...)
		case *ast.LabeledStmt:
			current = a.checkBlock([]ast.Stmt{value.Stmt}, current)
		case *ast.SendStmt:
			a.report(value, current, "channel send")
			a.checkBlockingExpressions(value.Value, current)
		default:
			a.checkBlockingExpressions(statement, current)
		}
	}
	return current
}

func analyzeFile(path string) ([]string, error) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	analyzer := &analyzer{fset: fset}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Body != nil {
			analyzer.checkBlock(function.Body.List, make(lockSet))
		}
	}
	return analyzer.diagnostics, nil
}

func run(paths []string) error {
	var diagnostics []string
	for _, root := range paths {
		// CLI arguments intentionally select the directories to audit.
		//nolint:gosec
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			found, err := analyzeFile(path)
			if err != nil {
				return err
			}
			diagnostics = append(diagnostics, found...)
			return nil
		})
		if err != nil {
			return err
		}
	}
	for _, diagnostic := range diagnostics {
		fmt.Fprintln(os.Stderr, diagnostic)
	}
	if len(diagnostics) != 0 {
		return fmt.Errorf("found %d blocking operation(s) under lifecycle/state locks", len(diagnostics))
	}
	return nil
}

func main() {
	paths := os.Args[1:]
	if len(paths) == 0 {
		paths = []string{"./tubes", "./transport"}
	}
	if err := run(paths); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
