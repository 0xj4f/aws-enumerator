import ast, sys, os, statistics, collections
ROOT = sys.argv[1]
def funcs(path):
    src = open(path).read()
    tree = ast.parse(src)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node.name, node.lineno, node.end_lineno, node.end_lineno - node.lineno + 1, node))
    return tree, out

pp = os.path.join(ROOT, 'app/components/policy_parser.py')
tree, fs = funcs(pp)
top = [f for f in fs if f[4] in tree.body]
print("policy_parser: top-level funcs", len(top), "all funcs incl nested", len(fs))
lens = sorted([f[3] for f in top])
print("median", statistics.median(lens), "mean", round(statistics.mean(lens),1), "max", max(lens))
print(">=100 lines:", sum(1 for l in lens if l>=100), ">=50:", sum(1 for l in lens if l>=50))
print("lines in funcs >=100:", sum(l for l in lens if l>=100))
for name, s, e, n, node in sorted(top, key=lambda x:-x[3])[:20]:
    # cyclomatic-ish: count branches
    br = sum(isinstance(x,(ast.If,ast.For,ast.While,ast.Try,ast.BoolOp,ast.IfExp,ast.comprehension)) for x in ast.walk(node))
    depth = 0
    def d(n, lvl=0):
        global depth
        if isinstance(n,(ast.For,ast.While,ast.If,ast.With,ast.Try)):
            lvl += 1
            depth = max(depth,lvl)
        for c in ast.iter_child_nodes(n): d(c,lvl)
    d(node)
    print(f"{name:45s} {s:5d}-{e:5d} {n:4d} lines  branches={br:3d} max_nest={depth}")
# nested defs
nested = [f for f in fs if f[4] not in tree.body]
print("nested defs:", collections.Counter(f[0] for f in nested))
# module-level constants
consts = [n for n in tree.body if isinstance(n, ast.Assign)]
print("module-level assigns:", len(consts), [ (t.id if isinstance(t,ast.Name) else '?') for n in consts for t in n.targets][:80])
# type hints
ann = 0; total=0
for root, _, files in os.walk(os.path.join(ROOT,'app')):
    for fn in files:
        if fn.endswith('.py'):
            t = ast.parse(open(os.path.join(root,fn)).read())
            for n in ast.walk(t):
                if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    total+=1
                    if n.returns or any(a.annotation for a in n.args.args):
                        ann+=1
print("functions total", total, "annotated", ann)
