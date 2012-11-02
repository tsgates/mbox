pyflakes $(find -name "*.py")|grep -v "redefinition of unused"|grep -v "__init__.*imported but unused"
