// Command witdump prints the resolved caddy:plugin WIT model (interfaces,
// functions, core signatures, layouts) as seen by go.bytecodealliance.org/wit.
// It exists to ground the hand-written descriptors in runtime/gen and will be
// superseded by a real witgen code generator.
package main

import (
	"fmt"

	"go.bytecodealliance.org/wit"
)

func main() {
	res, err := wit.LoadJSON("/home/a/repo/github.com/elee1766/caddy-wit/wit/caddy-plugin.wit.json")
	if err != nil {
		panic(err)
	}
	for _, w := range res.Worlds {
		if w.Name != "full-plugin" {
			continue
		}
		fmt.Printf("WORLD %s pkg=%s\n", w.Name, w.Package.Name.String())
		fmt.Println("IMPORTS:")
		w.Imports.All()(func(name string, item wit.WorldItem) bool {
			fmt.Printf("  key=%q item=%T\n", name, item)
			if ref, ok := item.(*wit.InterfaceRef); ok {
				dumpIface(ref.Interface)
			}
			return true
		})
		fmt.Println("EXPORTS:")
		w.Exports.All()(func(name string, item wit.WorldItem) bool {
			fmt.Printf("  key=%q item=%T\n", name, item)
			if ref, ok := item.(*wit.InterfaceRef); ok {
				dumpIface(ref.Interface)
			}
			return true
		})
	}
}

func dumpIface(i *wit.Interface) {
	name := "<anon>"
	if i.Name != nil {
		name = *i.Name
	}
	fmt.Printf("    iface %s pkg=%s\n", name, i.Package.Name.String())
	i.TypeDefs.All()(func(tn string, td *wit.TypeDef) bool {
		ownerName := "?"
		if o, ok := td.Owner.(*wit.Interface); ok && o.Name != nil {
			ownerName = *o.Name
		}
		fmt.Printf("      typedef %q kind=%T size=%d align=%d flat=%v owner=%s root-owner=%v\n", tn, td.Kind, td.Size(), td.Align(), flatStr(td.Flat()), ownerName, rootOwner(td))
		return true
	})
	i.Functions.All()(func(fn string, f *wit.Function) bool {
		fmt.Printf("      func key=%q Name=%q BaseName=%q Kind=%T method=%v static=%v\n", fn, f.Name, f.BaseName(), f.Kind, f.IsMethod(), f.IsStatic())
		cfLower := f.CoreFunction(wit.Imported)
		cfLift := f.CoreFunction(wit.Exported)
		fmt.Printf("        core imported: name=%q params=%v results=%v\n", cfLower.Name, paramsStr(cfLower.Params), paramsStr(cfLower.Results))
		fmt.Printf("        core exported: name=%q params=%v results=%v\n", cfLift.Name, paramsStr(cfLift.Params), paramsStr(cfLift.Results))
		if pr := f.PostReturn(wit.Exported); pr != nil {
			fmt.Printf("        post-return exported: name=%q\n", pr.Name)
		}
		return true
	})
}

func rootOwner(td *wit.TypeDef) string {
	r := td.Root()
	if o, ok := r.Owner.(*wit.Interface); ok && o.Name != nil {
		return *o.Name
	}
	return "?"
}

func paramsStr(ps []wit.Param) []string {
	var out []string
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s:%T", p.Name, p.Type))
	}
	return out
}

func flatStr(ts []wit.Type) []string {
	var out []string
	for _, t := range ts {
		out = append(out, fmt.Sprintf("%T", t))
	}
	return out
}
