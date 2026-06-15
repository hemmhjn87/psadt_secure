import ast
import os
from pathlib import Path

def get_imports(filepath):
    imports = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
        except SyntaxError:
            return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)
    return imports

def main():
    root_dir = Path(r"d:\project\psadt-secure")
    py_files = list(root_dir.rglob("*.py"))
    
    # Filter out virtual envs or unrelated
    py_files = [f for f in py_files if 'venv' not in f.parts and '.git' not in f.parts and '__pycache__' not in f.parts]
    
    # Internal modules
    internal_modules = set()
    for f in py_files:
        rel = f.relative_to(root_dir)
        mod = ".".join(rel.with_suffix("").parts)
        if mod.endswith(".__init__"):
            mod = mod[:-9]
        internal_modules.add(mod)
        # Also just the file names without extension
        internal_modules.add(f.stem)

    edges = []
    
    print("```mermaid")
    print("graph TD")
    print("    %% Nodes")
    for f in py_files:
        name = f.stem
        if name == "__init__":
            name = f.parent.name + "_init"
        print(f"    {name}[\"{f.name}\"]")
        
    print("    %% Edges")
    for f in py_files:
        name = f.stem
        if name == "__init__":
            name = f.parent.name + "_init"
            
        imports = get_imports(f)
        for imp in imports:
            # We want to link only to internal modules
            target = None
            if imp in internal_modules:
                target = imp
            else:
                # Handle src.scanners.xxx
                parts = imp.split('.')
                last = parts[-1]
                if last in internal_modules:
                    target = last
                elif parts[0] in internal_modules:
                    target = parts[0]
            
            if target:
                if target == "__init__":
                    continue
                print(f"    {name} --> {target}")

    print("```")

if __name__ == "__main__":
    main()
