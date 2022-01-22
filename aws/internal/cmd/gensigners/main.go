package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/lestrrat-go/codegen"
)

func main() {
	if err := _main(); err != nil {
		fmt.Printf("%s", err.Error())
		os.Exit(1)
	}
}

func yaml2json(fn string) ([]byte, error) {
	in, err := os.Open(fn)
	if err != nil {
		return nil, fmt.Errorf(`failed to open %q: %w`, fn, err)
	}
	defer in.Close()

	var v interface{}
	if err := yaml.NewDecoder(in).Decode(&v); err != nil {
		return nil, fmt.Errorf(`failed to decode %q: %w`, fn, err)
	}

	return json.Marshal(v)
}

func stringFromField(f codegen.Field, field string) (string, error) {
	v, ok := f.Extra(field)
	if !ok {
		return "", fmt.Errorf("%q does not exist in %q", field, f.Name(true))
	}

	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%q should be a string in %q", field, f.Name(true))
	}
	return s, nil
}

func _main() error {
	var objectsFile = flag.String("objects", "objects.yml", "")
	flag.Parse()
	jsonSrc, err := yaml2json(*objectsFile)
	if err != nil {
		return err
	}

	var def struct {
		Objects []*codegen.Object `json:"objects"`
	}
	if err := json.NewDecoder(bytes.NewReader(jsonSrc)).Decode(&def); err != nil {
		return fmt.Errorf(`failed to decode %q: %w`, *objectsFile, err)
	}

	for _, object := range def.Objects {
		object.Organize()
		if err := generateSigner(object); err != nil {
			return fmt.Errorf(`failed to generate object %q: %w`, object.Name(true), err)
		}
	}
	return nil
}

func generateSigner(obj *codegen.Object) error {
	var buf bytes.Buffer
	o := codegen.NewOutput(&buf)

	o.L(`package awssigner`)
	for _, field := range obj.Fields() {
		comment := field.Comment()
		if comment == "" {
			o.LL(`// With%s associates a new %s with the object, which will be used for Sign() and Public()`, field.GetterMethod(true), field.Type())
		} else {
			scanner := bufio.NewScanner(strings.NewReader(comment))
			count := 0
			for scanner.Scan() {
				line := scanner.Text()
				if count == 0 {
					o.LL(`// %s`, line)
				} else {
					o.L(`// %s`, line)
				}
				count++
			}
		}
		o.L(`func (cs *%[1]s) With%[2]s(v %[3]s) *%[1]s {`, obj.Name(true), field.GetterMethod(true), field.Type())
		o.L(`return &%s{`, obj.Name(true))
		o.L(`client: cs.client,`)
		for _, finner := range obj.Fields() {
			if finner.Name(false) == field.Name(false) {
				o.L(`%s: v,`, finner.Name(false))
			} else {
				o.L(`%[1]s: cs.%[1]s,`, finner.Name(false))
			}
		}
		o.L(`}`)
		o.L(`}`)
	}

	fn := fmt.Sprintf(`%s_gen.go`, strings.ToLower(obj.Name(false)))
	if err := o.WriteFile(fn, codegen.WithFormatCode(true)); err != nil {
		if cfe, ok := err.(codegen.CodeFormatError); ok {
			fmt.Fprint(os.Stderr, cfe.Source())
		}
		return fmt.Errorf(`failed to write to %s: %w`, fn, err)
	}
	return nil
}
