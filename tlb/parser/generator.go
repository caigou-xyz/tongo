package parser

import (
	"fmt"
	"github.com/startfellows/tongo/utils"
	"go/format"
	"strconv"
	"strings"
)

type DefaultType struct {
	Name          string
	IsPointerType bool
}

type Generator struct {
	knownTypes  map[string]DefaultType
	newTlbTypes []string
	typeName    string
}

var (
	defaultKnownTypes = map[string]DefaultType{
		"#":           {"uint32", false},
		"int8":        {"int8", false},
		"int16":       {"int16", false},
		"int32":       {"int32", false},
		"int64":       {"int64", false},
		"uint8":       {"uint8", false},
		"uint16":      {"uint16", false},
		"uint32":      {"uint32", false},
		"uint64":      {"uint64", false},
		"Bool":        {"bool", false},
		"Cell":        {"tlb.Any", false},
		"MsgAddress":  {"tlb.MsgAddress", false},
		"Coins":       {"tlb.Grams", false},
		"Text":        {"tlb.Text", false},
		"SnakeData":   {"tlb.SnakeData", false},
		"ChunkedData": {"tlb.ChunkedData", false},
		"DNSRecord":   {"tlb.DNSRecord", false},
	}
)

func NewGenerator(knownTypes map[string]DefaultType, typeName string) *Generator {
	if knownTypes == nil {
		knownTypes = defaultKnownTypes
	}
	return &Generator{
		knownTypes: knownTypes,
		typeName:   typeName,
	}
}

func (g *Generator) LoadTypes(declarations []CombinatorDeclaration, typePrefix string, skipMagic bool) (string, error) {
	return generateGolangTypes(declarations, typePrefix, skipMagic)
}

func generateGolangTypes(declarations []CombinatorDeclaration, typePrefix string, skipMagic bool) (string, error) {
	dec := make([][]CombinatorDeclaration, 0)
	for _, c := range declarations {
		if len(c.Combinator.TypeExpressions) > 0 {
			return "", fmt.Errorf("combinators with paramaters '%v' are not supported", c.Combinator.Name)
		}
		f := false
		for i, c1 := range dec {
			if c1[0].Combinator.Name == c.Combinator.Name {
				dec[i] = append(dec[i], c)
				f = true
				break
			}
		}
		if !f {
			dec = append(dec, []CombinatorDeclaration{c})
		}
	}
	s := ""

	for _, v := range dec {
		t, err := generateGolangType(v, typePrefix, skipMagic)
		if err != nil {
			return "", err
		}
		s += "\n\n" + t
	}

	b, err := format.Source([]byte(s))
	if err != nil {
		return s, err
	}
	return string(b), err
}

func generateGolangStruct(declaration CombinatorDeclaration, skipMagic bool) (string, error) {
	builder := strings.Builder{}
	builder.WriteString("struct{")
	if len(declaration.FieldDefinitions) > 0 {
		builder.WriteRune('\n')
	}

	if !skipMagic && declaration.Constructor.Prefix != "" && declaration.Constructor.Prefix != "#_" && declaration.Constructor.Prefix != "$_" {
		builder.WriteString(fmt.Sprintf("Magic tlb.Magic `tlb:\"%v\"`\n", declaration.Constructor.Prefix))
	}

	for i, field := range declaration.FieldDefinitions {
		if field.IsEmpty() {
			return "", fmt.Errorf("all types are nil in field %v in %v", i, declaration.Constructor.Name)
		}
		if field.Implicit != nil {
			continue
		}
		var name string
		var e TypeExpression
		if field.CellRef != nil {
			e = field.CellRef.TypeExpression
		} else if field.NamedField != nil {
			name = field.NamedField.Name
			e = field.NamedField.Expression
		}
		if name == "" || name == "_" {
			name = fmt.Sprintf("Field%v", i)
		}
		builder.WriteString(utils.ToCamelCase(name))
		builder.WriteRune('\t')
		t, err := e.toGolangType()
		if err != nil {
			return "", err
		}
		builder.WriteString(t.String())
		_ = e
		builder.WriteRune('\n')
	}
	builder.WriteRune('}')
	return builder.String(), nil
}

func generateGolangSimpleType(declaration CombinatorDeclaration, typePrefix string, skipMagic bool) (string, error) {
	s, err := generateGolangStruct(declaration, skipMagic)
	return fmt.Sprintf("type %s%v %v", utils.ToCamelCase(typePrefix), declaration.Combinator.Name, s), err
}

func generateGolangSumType(declarations []CombinatorDeclaration, typePrefix string) (string, error) {
	builder := strings.Builder{}
	builder.WriteString("type " + utils.ToCamelCase(typePrefix) + declarations[0].Combinator.Name + " struct{\ntlb.SumType\n")
	for _, d := range declarations {
		s, err := generateGolangStruct(d, true)
		if err != nil {
			return "", err
		}
		builder.WriteString(utils.ToCamelCase(d.Constructor.Name))
		builder.WriteRune(' ')
		builder.WriteString(s)
		builder.WriteString(fmt.Sprintf(" `tlbSumType:\"%v\"`", d.Constructor.Prefix))
		builder.WriteRune('\n')
	}
	builder.WriteRune('}')
	return builder.String(), nil

}

func generateGolangType(declarations []CombinatorDeclaration, typePrefix string, skipMagic bool) (string, error) {
	if len(declarations) == 1 {
		return generateGolangSimpleType(declarations[0], typePrefix, skipMagic)
	} else {
		return generateGolangSumType(declarations, typePrefix)
	}
}

type golangType struct {
	name   string
	tag    string
	params []golangType
}

func (t TypeExpression) toGolangType() (golangType, error) {
	if t.ParenExpression != nil {
		return t.ParenExpression.toGolangType()
	}
	if t.NamedRef != nil {
		return mapToGoType(*t.NamedRef, false), nil
	}
	if t.BuiltIn != nil {
		return mapToGoType(*t.BuiltIn, false), nil
	}
	if t.Number != nil {
		return mapToGoType(fmt.Sprintf("%d", *t.Number), false), nil
	}
	if t.CellRef != nil {
		gt, err := t.CellRef.TypeExpression.toGolangType()
		if err != nil {
			return golangType{}, err
		}
		return golangType{
			name: fmt.Sprintf("tlb.Ref[%s]", gt.String()),
			tag:  "",
		}, nil
	}

	return golangType{
		name: "UnknownType",
		tag:  "",
	}, nil
}

func (t *ParenExpression) toGolangType() (golangType, error) {
	var res golangType
	name, err := t.Name.toGolangType()
	if err != nil {
		return golangType{}, err
	}
	res.name = name.String()
	switch name.String() {
	case "Either":
		if len(t.Parameter) != 2 {
			return golangType{}, fmt.Errorf("invalid parameters qty for Either")
		}
		p1, err := t.Parameter[0].toGolangType()
		if err != nil {
			return golangType{}, err
		}
		p2, err := t.Parameter[1].toGolangType()
		if err != nil {
			return golangType{}, err
		}
		if fmt.Sprintf("tlb.Ref[%s]", p1.String()) == p2.String() {
			res.name = fmt.Sprintf("tlb.EitherRef[%s]", p1.String())
			return res, nil
		}
		res.name = fmt.Sprintf("tlb.Either[%s, %s]", p1.String(), p2.String())
		return res, nil
	case "HashmapE":
		if len(t.Parameter) != 2 {
			return golangType{}, fmt.Errorf("invalid parameters qty for HashmapE")
		}
		if t.Parameter[0].Number == nil {
			return golangType{}, fmt.Errorf("invalid bitsize type for HashmapE")
		}
		size := mapBitsSizeToType(*t.Parameter[0].Number)
		p, err := t.Parameter[1].toGolangType()
		if err != nil {
			return golangType{}, err
		}
		res.name = fmt.Sprintf("tlb.HashmapE[%s, %s]", size.String(), p.String())
		return res, nil
	case "Maybe":
		if len(t.Parameter) != 1 {
			return golangType{}, fmt.Errorf("invalid parameters qty for Maybe")
		}
		p, err := t.Parameter[0].toGolangType()
		if err != nil {
			return golangType{}, err
		}
		res.name = fmt.Sprintf("tlb.Maybe[%s]", p.String())
		return res, nil
	case "VarUInteger":
		if len(t.Parameter) != 1 {
			return golangType{}, fmt.Errorf("invalid parameters qty for VarUInteger")
		}
		p, err := t.Parameter[0].toGolangType()
		if err != nil {
			return golangType{}, err
		}
		res.name = fmt.Sprintf("tlb.VarUInteger%s", p.String())
		return res, nil
	case "##":
		if len(t.Parameter) != 1 {
			return golangType{}, fmt.Errorf("invalid parameters qty for ##")
		}
		p, err := t.Parameter[0].toGolangType()
		if err != nil {
			return golangType{}, err
		}
		size := p.String()
		if size == "8" || size == "16" || size == "32" || size == "64" {
			res.name = fmt.Sprintf("uint%s", p.String())
		} else {
			res.name = fmt.Sprintf("tlb.Uint%s", p.String())
		}
		return res, nil
	}

	for _, p := range t.Parameter {
		param, err := p.toGolangType()
		if err != nil {
			return golangType{}, err
		}
		res.params = append(res.params, param)
	}
	return res, nil
}

func mapBitsSizeToType(bits int) golangType {
	if bits <= 64 {
		return golangType{
			name: fmt.Sprintf("tlb.Uint%d", bits),
		}
	}
	return golangType{
		name: fmt.Sprintf("tlb.Bits%d", bits),
	}
}

func mapToGoType(name string, optional bool) golangType {
	goType, ok := defaultKnownTypes[name] // TODO: replace to generator field
	if ok {
		return golangType{
			name: goType.Name,
		}
	}
	t, ok := parseBuildInInt(name)
	if ok {
		return t
	}
	if name == "##" {
		return golangType{
			name: name,
		}
	}
	return golangType{
		name: utils.ToCamelCase(name),
	}
}

func parseBuildInInt(s string) (golangType, bool) {
	if strings.HasPrefix(s, "int") {
		last := strings.TrimPrefix(s, "int")
		bits, err := strconv.Atoi(last)
		if err != nil {
			return golangType{}, false
		}
		return golangType{
			name: fmt.Sprintf("tlb.Int%d", bits),
		}, true
	}

	if strings.HasPrefix(s, "uint") {
		last := strings.TrimPrefix(s, "uint")
		bits, err := strconv.Atoi(last)
		if err != nil {
			return golangType{}, false
		}
		return golangType{
			name: fmt.Sprintf("tlb.Uint%d", bits),
		}, true
	}

	if strings.HasPrefix(s, "bits") {
		last := strings.TrimPrefix(s, "bits")
		bits, err := strconv.Atoi(last)
		if err != nil {
			return golangType{}, false
		}
		return golangType{
			name: fmt.Sprintf("tlb.Bits%d", bits),
		}, true
	}

	return golangType{}, false
}

func (t golangType) String() string {
	switch t.name {
	default:
		return t.name
	}
}
