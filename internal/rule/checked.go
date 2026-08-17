package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/proto"
)

const (
	maxCheckedExpressionSize  = 4 * 1024 * 1024
	maxCheckedExpressionCount = 1024
	maxCheckedCatalogSize     = 64 * 1024 * 1024
)

// checkedExpressionLocationPrefix versions generated expressions against
// Numbat's CEL declarations and AST validation contract. Bump the revision
// when either changes incompatibly.
const checkedExpressionLocationPrefix = "numbat:cel-env-v1:sha256:"

// CheckedExpressions holds trusted, build-generated CEL expressions keyed by
// the SHA-256 digest of their exact source text. The digest and location marker
// catch stale data; they are not authentication for user-supplied protobufs.
type CheckedExpressions map[[sha256.Size]byte][]byte

// BuildCheckedExpressions validates and type-checks every distinct expression
// in sources, returning deterministic protobuf encodings suitable for
// embedding. NewEngineWithCheckedExpressions still constructs runtime CEL
// programs and applies current program options when loading them.
func BuildCheckedExpressions(sources []Source) (CheckedExpressions, error) {
	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}

	checked := make(CheckedExpressions)
	seenIDs := make(map[string]string)
	for _, source := range sources {
		for i := range source.Rules {
			r := cloneRule(source.Rules[i])
			if err := validateRule(r); err != nil {
				return nil, err
			}
			if previous, ok := seenIDs[r.ID]; ok {
				return nil, fmt.Errorf("duplicate rule id %q: defined in source %s and source %s", r.ID, previous, sourceLabel(source))
			}
			seenIDs[r.ID] = sourceLabel(source)

			for _, expr := range ruleExpressions(r) {
				digest := sha256.Sum256([]byte(expr))
				if _, ok := checked[digest]; ok {
					continue
				}
				ast, err := checkExpr(env, expr)
				if err != nil {
					return nil, fmt.Errorf("rule %q: %w", r.ID, err)
				}
				if _, err := programExpr(env, ast); err != nil {
					return nil, fmt.Errorf("rule %q: %w", r.ID, err)
				}
				pb, err := cel.AstToCheckedExpr(ast)
				if err != nil {
					return nil, fmt.Errorf("rule %q: serialize checked expr: %w", r.ID, err)
				}
				if pb.SourceInfo == nil {
					pb.SourceInfo = new(exprpb.SourceInfo)
				}
				pb.SourceInfo.Location = checkedExpressionLocationPrefix + hex.EncodeToString(digest[:])
				data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(pb)
				if err != nil {
					return nil, fmt.Errorf("rule %q: serialize checked expr: %w", r.ID, err)
				}
				if len(data) > maxCheckedExpressionSize {
					return nil, fmt.Errorf("rule %q: checked expr exceeds %d bytes", r.ID, maxCheckedExpressionSize)
				}
				checked[digest] = data
			}
		}
	}
	return checked, nil
}

func ruleExpressions(r Rule) []string {
	if r.Sequence == nil {
		return []string{r.Expr}
	}
	expressions := make([]string, len(r.Sequence.Steps))
	for i, step := range r.Sequence.Steps {
		expressions[i] = step.Expr
	}
	return expressions
}

// LoadCheckedExpressionsFS loads deterministic *.pb files named by the
// lowercase SHA-256 digest of their source expression. The files contain only
// CEL's CheckedExpr protobuf; rule metadata remains in YAML.
func LoadCheckedExpressionsFS(fsys fs.FS, dir string) (CheckedExpressions, error) {
	var paths []string
	err := fs.WalkDir(fsys, dir, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && path.Ext(name) == ".pb" {
			paths = append(paths, name)
			if len(paths) > maxCheckedExpressionCount {
				return fmt.Errorf("more than %d checked expressions", maxCheckedExpressionCount)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk checked expressions %q: %w", dir, err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("checked expressions %q: no protobuf files found", dir)
	}

	checked := make(CheckedExpressions, len(paths))
	totalSize := 0
	for _, name := range paths {
		digest, err := checkedExpressionDigest(name)
		if err != nil {
			return nil, err
		}
		data, err := readCheckedExpression(fsys, name)
		if err != nil {
			return nil, err
		}
		totalSize += len(data)
		if totalSize > maxCheckedCatalogSize {
			return nil, fmt.Errorf("checked expressions %q: catalog exceeds %d bytes", dir, maxCheckedCatalogSize)
		}
		if _, duplicate := checked[digest]; duplicate {
			return nil, fmt.Errorf("duplicate checked expression digest %x", digest)
		}
		checked[digest] = data
	}
	return checked, nil
}

func checkedExpressionDigest(name string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	base := strings.TrimSuffix(path.Base(name), path.Ext(name))
	decoded, err := hex.DecodeString(base)
	if err != nil || len(decoded) != sha256.Size || base != strings.ToLower(base) {
		return digest, fmt.Errorf("checked expression %q: filename must be a lowercase SHA-256 digest plus .pb", name)
	}
	copy(digest[:], decoded)
	return digest, nil
}

func readCheckedExpression(fsys fs.FS, name string) ([]byte, error) {
	file, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open checked expression %q: %w", name, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxCheckedExpressionSize+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf("read checked expression %q: %w", name, errors.Join(readErr, closeErr))
	}
	if len(data) > maxCheckedExpressionSize {
		return nil, fmt.Errorf("read checked expression %q: exceeds %d bytes", name, maxCheckedExpressionSize)
	}
	return data, nil
}

func checkedExpressionAST(expr string, checked CheckedExpressions) (*cel.Ast, bool) {
	if len(checked) == 0 {
		return nil, false
	}
	digest := sha256.Sum256([]byte(expr))
	data, ok := checked[digest]
	if !ok {
		return nil, false
	}
	var pb exprpb.CheckedExpr
	if err := proto.Unmarshal(data, &pb); err != nil {
		return nil, false
	}
	if pb.GetSourceInfo().GetLocation() != checkedExpressionLocationPrefix+hex.EncodeToString(digest[:]) {
		return nil, false
	}
	ast, err := cel.CheckedExprToAstWithSource(&pb, nil)
	if err != nil {
		return nil, false
	}
	return ast, true
}
